//! Native NBP1901 adapter for the staged BM1398 executor.
//!
//! The daemon transfers its existing I2C worker, chain transports and FIFO
//! handles here. This module never opens a second I2C endpoint. Stock framed
//! PIC1704 app 0x89 is distinct from the short-form PIC1704 register dialect.
//! The held modern bosminer proves VERSION+0, CTRL+8 and WORK_TIME+0x14
//! for its bm13xx FPGA ABI. The loaded version/build are verified before use;
//! neither the carrier name nor BM1398 identity selects those registers.

#[path = "am2_bm1398_fpga.rs"]
pub mod fpga;

#[cfg(feature = "sim-hal")]
#[path = "am2_bm1398_simulation.rs"]
pub mod simulation;

use crate::chain_backend::Bm1397PlusChainBackend;
use crate::fpga_chain::FpgaChain;
use crate::i2c::{I2cMutationLabel, I2cServiceHandle, I2cTransactionStep};
use dcentrald_api_types::hashboard_eeprom::{
    decode_bm1398_factory_page, observed_protocol_from_bm1398_factory_page,
};
use dcentrald_common::s19_bm1398_runtime::{executor::*, Bm1398FpgaMidstateMode};
use dcentrald_common::TransportOp;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// The existing daemon safety owner, not a second fan/controller manager.
///
/// `start` must acquire cooling and independent thermal/power-cut custody and
/// verify that the already-owned command/FIFO handles match the loaded fabric
/// ABI before any chain command is issued.
/// `check_health` must reject stale/missing sensors and failed cooling, enforce
/// the configured fan ceiling, and remain usable while controller I/O waits.
/// `hash_power(false)` cuts the exact NBP1901 GPIO907 active-low gate during
/// prepared startup; `true` verifies its ON readback. `terminal_power_off`
/// cuts it permanently and fences late queued energization for this owner.
/// `chain_reset` operates the discovered slot's hash reset, never PIC RESET.
/// `stop` may release custody only after verified power-off. No defaults exist.
pub trait Am2Bm1398Custody: Send + Sync + 'static {
    fn start(&self, chains: &[u8]) -> impl Future<Output = Result<(), String>> + Send;
    fn check_health(&self) -> impl Future<Output = Result<(), String>> + Send;
    fn hash_power(&self, enabled: bool) -> impl Future<Output = Result<(), String>> + Send;
    fn terminal_power_off(&self) -> impl Future<Output = Result<(), String>> + Send;
    fn chain_reset(
        &self,
        chain: u8,
        asserted: bool,
    ) -> impl Future<Output = Result<(), String>> + Send;
    fn stop(&self) -> impl Future<Output = Result<(), String>> + Send;
}

pub struct Am2Bm1398ChainIo {
    pub commands: Arc<dyn Bm1397PlusChainBackend>,
    /// Must be the existing owner's handle opened for the observed fabric ABI.
    pub fifo: Arc<FpgaChain>,
}

/// Per-bin carrier facts the adapter joins on: the stock topol.conf `machine`
/// name returned as factory identity, the board_target marker this adapter
/// requires, and the population cap for the chip-address window. Counts are
/// the first-party stock topol.conf `chain.chain_asic_num` rows (NBP1901 114
/// at interval 2; NBS1902/NBT1903 76 at interval 3, Phase A §3.7 rows 7/9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Am2Bm1398BoardKind {
    Nbp1901,
    Nbs1902,
    Nbt1903,
    Bhb28611,
    Bhb28701,
}

impl Am2Bm1398BoardKind {
    pub fn from_board_target(board_target: &str) -> Result<Self, String> {
        match board_target {
            "am2-s19pro" => Ok(Self::Nbp1901),
            "am2-s19" => Ok(Self::Nbs1902),
            "am2-t19" => Ok(Self::Nbt1903),
            "am2-s19a" => Ok(Self::Bhb28611),
            "am2-s19plus" => Ok(Self::Bhb28701),
            other => Err(format!(
                "board target {other:?} has no BM1398 native family carrier"
            )),
        }
    }

    pub const fn board_target(self) -> &'static str {
        match self {
            Self::Nbp1901 => "am2-s19pro",
            Self::Nbs1902 => "am2-s19",
            Self::Nbt1903 => "am2-t19",
            Self::Bhb28611 => "am2-s19a",
            Self::Bhb28701 => "am2-s19plus",
        }
    }

    pub const fn stock_board_name(self) -> &'static str {
        match self {
            Self::Nbp1901 => "NBP1901",
            Self::Nbs1902 => "NBS1902",
            Self::Nbt1903 => "NBT1903",
            Self::Bhb28611 => "BHB28611",
            Self::Bhb28701 => "BHB28701",
        }
    }

    pub const fn chips_per_chain(self) -> u16 {
        match self {
            Self::Nbp1901 => 114,
            Self::Nbs1902 | Self::Nbt1903 => 76,
            Self::Bhb28611 => 72,
            Self::Bhb28701 => 80,
        }
    }
}

/// One retained PIC command lane shared by startup, heartbeat and temperature
/// reads. A blocking operation retains the lock through its failure flush even
/// when the awaiting Tokio task is cancelled. APW and EEPROM never use it.
#[derive(Clone)]
pub struct Nbp1901PicService {
    i2c: I2cServiceHandle,
    lane: Arc<Mutex<()>>,
}

impl Nbp1901PicService {
    pub fn new(i2c: I2cServiceHandle) -> Result<Self, String> {
        if i2c.bus() != 0 {
            return Err("NBP1901 PIC owner requires the retained bus-0 worker".into());
        }
        Ok(Self {
            i2c,
            lane: Arc::new(Mutex::new(())),
        })
    }

    async fn transaction(
        &self,
        chain: u8,
        label: I2cMutationLabel,
        steps: Vec<I2cTransactionStep>,
        terminal_disable: bool,
    ) -> Result<Vec<Vec<u8>>, String> {
        if chain > 2 {
            return Err("NBP1901 PIC slot is outside 0..2".into());
        }
        let owner = self.clone();
        tokio::task::spawn_blocking(move || {
            let _lane = owner.lane.lock().map_err(|_| "NBP1901 PIC lane poisoned")?;
            let address = 0x20 + chain;
            if terminal_disable && owner.i2c.terminal_safe_off_is_latched() {
                owner.i2c.disable_nbp1901_pic89_voltage(address).map_err(|e| e.to_string())?;
                return Ok(vec![vec![0x15], vec![1]]); // fixed worker verified the actual ACK
            }
            match owner.i2c.transaction_mutating(label, address, steps) {
                Ok(reads) => Ok(reads),
                Err(error) => {
                    if matches!(&error, crate::HalError::I2c { .. }) {
                        // Canonical PIC MSSP recovery: sixteen separate zero
                        // bytes after a NACK, before this lane can send another
                        // command. This never chooses a protected EEPROM.
                        if let Err(flush_error) = owner.i2c.transaction_mutating(
                            I2cMutationLabel::QueryPrelude,
                            address,
                            vec![I2cTransactionStep::WriteByteByByte(vec![0; 16])],
                        ) {
                            tracing::warn!(address, %flush_error, "NBP1901 PIC parser flush failed; original operation remains failed");
                        }
                    }
                    Err(error.to_string())
                }
            }
        })
        .await
        .map_err(|e| format!("NBP1901 PIC worker did not complete: {e}"))?
    }

    async fn exchange(&self, exchange: &Bm1398FramedExchange) -> Result<Vec<Vec<u8>>, String> {
        let Bm1398FramedEndpoint::Pic { chain } = exchange.endpoint else {
            return Err("NBP1901 PIC owner cannot execute an APW command".into());
        };
        let (label, _, steps) = stock_framed_transaction(exchange)?;
        let terminal_disable = exchange.request == [0x55, 0xaa, 5, 0x15, 0, 0, 0x1a];
        self.transaction(chain, label, steps, terminal_disable)
            .await
    }

    pub async fn read_version(&self, chain: u8) -> Result<Vec<u8>, String> {
        let reads = self
            .exchange(&Bm1398FramedExchange {
                endpoint: Bm1398FramedEndpoint::Pic { chain },
                request: vec![0x55, 0xaa, 4, 0x17, 0, 0x1b],
                response_bytes: 5,
            })
            .await?;
        Ok(reads.into_iter().flatten().collect())
    }

    pub async fn read_temperature(&self, chain: u8, sensor: u8) -> Result<Vec<u8>, String> {
        let reads = self
            .transaction(
                chain,
                I2cMutationLabel::QueryPrelude,
                nbp1901_temperature_steps(sensor)?,
                false,
            )
            .await?;
        Ok(reads.into_iter().flatten().collect())
    }
}

/// Stock 0x46ca0/0x48110 PIC-mediated LM75 pointer/write then two-byte read.
/// The fixed sensor range cannot select a factory EEPROM or PIC flash command.
pub fn nbp1901_temperature_steps(sensor: u8) -> Result<Vec<I2cTransactionStep>, String> {
    if !(0x48..=0x4b).contains(&sensor) {
        return Err("NBP1901 LM75 endpoint out of range".into());
    }
    let select_sum = 6_u16 + 0x3b + u16::from(sensor);
    let read_sum = 6_u16 + 0x3c + u16::from(sensor) + 2;
    let mut steps = vec![
        I2cTransactionStep::WriteByteByByte(vec![
            0x55,
            0xaa,
            6,
            0x3b,
            sensor,
            0,
            (select_sum >> 8) as u8,
            select_sum as u8,
        ]),
        I2cTransactionStep::SleepMs(10),
        I2cTransactionStep::Read(1),
        I2cTransactionStep::Read(1),
        I2cTransactionStep::SleepMs(10),
        I2cTransactionStep::WriteByteByByte(vec![
            0x55,
            0xaa,
            6,
            0x3c,
            sensor,
            2,
            (read_sum >> 8) as u8,
            read_sum as u8,
        ]),
        I2cTransactionStep::SleepMs(10),
    ];
    steps.extend((0..7).map(|_| I2cTransactionStep::Read(1)));
    Ok(steps)
}

pub struct Am2Bm1398Io<C: Am2Bm1398Custody> {
    i2c: I2cServiceHandle,
    pic: Nbp1901PicService,
    chains: BTreeMap<u8, Am2Bm1398ChainIo>,
    custody: Arc<C>,
    board: Am2Bm1398BoardKind,
    heartbeat_chains: Arc<Mutex<Vec<u8>>>,
    health_fault: Arc<Mutex<Option<String>>>,
    cancel: CancellationToken,
    watcher: Option<JoinHandle<Result<(), String>>>,
    configured: BTreeMap<u8, usize>,
    factory_pages: BTreeMap<u8, Vec<u8>>,
}

impl<C: Am2Bm1398Custody> Am2Bm1398Io<C> {
    /// System image identity is read here, never accepted from an API model
    /// string. Physical factory identity and controller replies are checked by
    /// the startup executor before work is available. Retained NBP1901 form.
    pub async fn from_system(
        pic: Nbp1901PicService,
        chains: BTreeMap<u8, Am2Bm1398ChainIo>,
        custody: Arc<C>,
    ) -> Result<Self, String> {
        Self::from_system_for_board(pic, chains, custody, Am2Bm1398BoardKind::Nbp1901).await
    }

    /// The same carrier admission for the whole BM1398 native family. The
    /// system image identity is still read from `/etc/dcentos/board_target`
    /// here; the board kind only selects which exact marker is required and
    /// which factory name/population the identity joins pin.
    pub async fn from_system_for_board(
        pic: Nbp1901PicService,
        chains: BTreeMap<u8, Am2Bm1398ChainIo>,
        custody: Arc<C>,
        board: Am2Bm1398BoardKind,
    ) -> Result<Self, String> {
        let marker =
            tokio::task::spawn_blocking(|| std::fs::read_to_string("/etc/dcentos/board_target"))
                .await
                .map_err(|e| e.to_string())?
                .map_err(|e| e.to_string())?;
        Self::from_observed_marker(pic, chains, custody, board, &marker)
    }

    // Shared exact checks. The only injected-marker caller is the sim-hal
    // fixture that owns the I2C worker and verifies every command/FIFO backing.
    fn from_observed_marker(
        pic: Nbp1901PicService,
        chains: BTreeMap<u8, Am2Bm1398ChainIo>,
        custody: Arc<C>,
        board: Am2Bm1398BoardKind,
        marker: &str,
    ) -> Result<Self, String> {
        let i2c = pic.i2c.clone();
        if marker.trim() != board.board_target()
            || i2c.bus() != 0
            || chains.is_empty()
            || chains.len() > 3
            || chains.iter().any(|(&slot, io)| {
                slot > 2 || io.commands.chain_id() != slot || io.fifo.chain_id != slot
            })
        {
            return Err(
                "BM1398 native family requires exact system image, bus 0 and unique physical slots 0..2"
                    .into(),
            );
        }
        for io in chains.values() {
            fpga::validate_fabric(&io.fifo)?;
        }
        Ok(Self {
            i2c,
            pic,
            chains,
            custody,
            board,
            heartbeat_chains: Arc::new(Mutex::new(vec![])),
            health_fault: Arc::new(Mutex::new(None)),
            cancel: CancellationToken::new(),
            watcher: None,
            configured: BTreeMap::new(),
            factory_pages: BTreeMap::new(),
        })
    }

    fn chain(&self, chain: u8) -> Result<&Am2Bm1398ChainIo, String> {
        self.chains
            .get(&chain)
            .ok_or_else(|| format!("chain slot {chain} is not owned"))
    }

    async fn check_health(&self) -> Result<(), String> {
        if let Some(fault) = self
            .health_fault
            .lock()
            .map_err(|_| "health lock poisoned")?
            .clone()
        {
            return Err(fault);
        }
        self.custody.check_health().await
    }

    fn start_watcher(&mut self) {
        let i2c = self.i2c.clone();
        let pic = self.pic.clone();
        let custody = self.custody.clone();
        let chains = self.heartbeat_chains.clone();
        let fault = self.health_fault.clone();
        let cancel = self.cancel.clone();
        self.watcher = Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                }
                let result = async {
                    custody.check_health().await?;
                    let current = chains
                        .lock()
                        .map_err(|_| "PIC schedule lock poisoned")?
                        .clone();
                    for chain in current {
                        let reply = execute_framed(
                            &i2c,
                            &pic,
                            &Bm1398FramedExchange {
                                endpoint: Bm1398FramedEndpoint::Pic { chain },
                                request: vec![0x55, 0xaa, 4, 0x16, 0, 0x1a],
                                response_bytes: 6,
                            },
                        )
                        .await?;
                        if reply[1] != 0x16 || reply[2] != 1 {
                            return Err("periodic PIC heartbeat failed".into());
                        }
                    }
                    Ok::<(), String>(())
                }
                .await;
                if let Err(error) = result {
                    if let Ok(mut state) = fault.lock() {
                        *state = Some(error);
                    }
                    break;
                }
            }
            // This independent task retains custody even if startup/work is
            // cancelled or the adapter is dropped. Power goes first.
            custody.terminal_power_off().await?;
            custody.stop().await
        }));
    }

    /// Poll the very same owned WORK_RX FIFO used for dispatch. The caller's
    /// BM1398 dispatcher validates work-id/midstate attribution and shares.
    pub async fn poll_nonce(&self, chain: u8) -> Result<Option<(u32, u32)>, String> {
        if !self.configured.contains_key(&chain) {
            return Err("chain work codec is not configured".into());
        }
        self.check_health().await?;
        Ok(self.chain(chain)?.fifo.read_nonce())
    }
}

impl<C: Am2Bm1398Custody> Drop for Am2Bm1398Io<C> {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Fixed request grammar. No caller can use this route to send PIC reset,
/// jump/flash bytes or an arbitrary APW command.
pub fn stock_framed_transaction(
    exchange: &Bm1398FramedExchange,
) -> Result<(I2cMutationLabel, u8, Vec<I2cTransactionStep>), String> {
    let (label, address, mut steps) = match exchange.endpoint {
        Bm1398FramedEndpoint::Pic { chain } if chain < 3 => {
            let label = match exchange.request.as_slice() {
                [0x55, 0xaa, 4, 0x17, 0, 0x1b] if exchange.response_bytes == 5 => {
                    I2cMutationLabel::QueryPrelude
                }
                [0x55, 0xaa, 4, 0x16, 0, 0x1a] if exchange.response_bytes == 6 => {
                    I2cMutationLabel::KeepAlive
                }
                [0x55, 0xaa, 5, 0x15, 0, 0, 0x1a] if exchange.response_bytes == 2 => {
                    I2cMutationLabel::NeutralControl
                }
                [0x55, 0xaa, 5, 0x15, 1, 0, 0x1b] if exchange.response_bytes == 2 => {
                    I2cMutationLabel::Energize
                }
                _ => return Err("unsupported stock PIC request".into()),
            };
            (
                label,
                0x20 + chain,
                vec![
                    I2cTransactionStep::WriteByteByByte(exchange.request.clone()),
                    I2cTransactionStep::SleepMs(300),
                ],
            )
        }
        Bm1398FramedEndpoint::Apw12 => {
            if exchange.response_bytes != 8 {
                return Err("APW response must contain eight bytes".into());
            }
            let label = match exchange.request.as_slice() {
                [0x55, 0xaa, 4, 2, 6, 0] => I2cMutationLabel::QueryPrelude,
                [0x55, 0xaa, 6, 0x83, code, 0, lo, hi]
                    if u16::from_le_bytes([*lo, *hi]) == u16::from(*code) + 0x89
                        // Union of the held NBP1901/NBS1902/NBT1903 stock
                        // levels.json rail levels; the per-bin (frequency,
                        // rail) pair is bounded by the executor config.
                        && [
                            1240, 1250, 1260, 1270, 1280, 1290, 1300, 1310,
                            1320, 1330, 1340, 1350, 1360, 1380, 1400, 1420, 1440,
                        ]
                        .iter()
                        .any(|&v| apw12_stock71_rail_code(v).ok() == Some(*code)) =>
                {
                    I2cMutationLabel::Energize
                }
                _ => return Err("unsupported stock APW request".into()),
            };
            let mut steps: Vec<_> = exchange
                .request
                .iter()
                .map(|&byte| I2cTransactionStep::Write(vec![0x11, byte]))
                .collect();
            steps.push(I2cTransactionStep::SleepMs(400));
            (label, 0x10, steps)
        }
        _ => return Err("unknown stock controller endpoint".into()),
    };
    for _ in 0..exchange.response_bytes {
        steps.push(match exchange.endpoint {
            Bm1398FramedEndpoint::Pic { .. } => I2cTransactionStep::Read(1),
            Bm1398FramedEndpoint::Apw12 => I2cTransactionStep::WriteRead {
                write_data: vec![0x11],
                read_len: 1,
            },
        });
    }
    if exchange.endpoint == Bm1398FramedEndpoint::Apw12 {
        steps.push(I2cTransactionStep::SleepMs(100));
    }
    Ok((label, address, steps))
}

async fn execute_framed(
    i2c: &I2cServiceHandle,
    pic: &Nbp1901PicService,
    exchange: &Bm1398FramedExchange,
) -> Result<Vec<u8>, String> {
    let (label, address, steps) = stock_framed_transaction(exchange)?;
    let reads = match exchange.endpoint {
        Bm1398FramedEndpoint::Pic { .. } => pic.exchange(exchange).await?,
        Bm1398FramedEndpoint::Apw12 => i2c
            .async_handle()
            .transaction_mutating(label, address, steps)
            .await
            .map_err(|e| e.to_string())?,
    };
    if reads.len() != exchange.response_bytes || reads.iter().any(|r| r.len() != 1) {
        return Err("controller exchange returned a partial byte stream".into());
    }
    Ok(reads.into_iter().flatten().collect())
}

fn assigned_chip_address(body: &[u8]) -> Result<(u8, u16), String> {
    // ChipAddress word is big-endian 0x139818AA; register echo is zero.
    // The same command-response CRC5 is independently pinned by the locked
    // BM1398 unassigned body 13 98 18 00 00 00 04.
    if body.len() != 7
        || body[..3] != [0x13, 0x98, 0x18]
        || body[5] != 0
        || body[6] & 0xe0 != 0
        || dcentrald_common::s19k_bm1366_uart_rx::command_response_crc5(&body[..6]) != body[6]
    {
        return Err("invalid BM1398 register-zero reply".into());
    }
    Ok((body[3], 0x1398))
}

fn misc_control_reply(body: &[u8]) -> Result<u32, String> {
    if body.len() != 7
        || body[4] != 0
        || body[5] != 0x18
        || body[6] & 0xe0 != 0
        || dcentrald_common::s19k_bm1366_uart_rx::command_response_crc5(&body[..6]) != body[6]
    {
        return Err("invalid BM1398 address-zero MiscControl reply".into());
    }
    Ok(u32::from_be_bytes(body[..4].try_into().unwrap()))
}

impl<C: Am2Bm1398Custody> Bm1398RuntimeIo for Am2Bm1398Io<C> {
    async fn execute(
        &mut self,
        action: &Bm1398RuntimeAction,
    ) -> Result<Bm1398RuntimeReply, String> {
        use Bm1398RuntimeAction as A;
        match action {
            A::VerifyFactoryIdentity { chain } => {
                self.chain(*chain)?;
                let service = self.i2c.clone();
                let address = 0x50 + *chain;
                let raw = tokio::task::spawn_blocking(move || {
                    service.read_hashboard_eeprom_page_at(
                        address,
                        Instant::now() + Duration::from_secs(2),
                    )
                })
                .await
                .map_err(|e| e.to_string())?
                .map_err(|e| e.to_string())?;
                let identity = decode_bm1398_factory_page(&raw).map_err(str::to_owned)?;
                self.factory_pages.insert(*chain, raw);
                return Ok(Bm1398RuntimeReply::FactoryIdentity {
                    stock_board_name: identity.board_name().map(str::to_owned),
                    serial: identity.serial().to_owned(),
                });
            }
            A::StartCustody { chains } => {
                if self.watcher.is_some() || self.cancel.is_cancelled() {
                    return Err("custody already used".into());
                }
                if chains.len() != self.chains.len()
                    || chains.iter().any(|c| !self.chains.contains_key(c))
                {
                    return Err("custody chain population disagrees with owned transports".into());
                }
                self.custody.start(chains).await?;
                self.start_watcher();
                for io in self.chains.values() {
                    let config = fpga::Bm1398FpgaWorkConfig::new(
                        Bm1398FpgaMidstateMode::Four,
                        Duration::from_millis(50),
                    )?;
                    config.apply(&io.fifo)?;
                    io.fifo.reset_fifos();
                }
            }
            A::MaintainPicHeartbeat { chain } => {
                self.chain(*chain)?;
                let mut chains = self
                    .heartbeat_chains
                    .lock()
                    .map_err(|_| "PIC schedule lock poisoned")?;
                if !chains.contains(chain) {
                    chains.push(*chain);
                }
            }
            A::WaitPsuReady => {
                let mut ready = false;
                for _ in 0..10 {
                    let reads = self
                        .i2c
                        .async_handle()
                        .transaction_mutating(
                            I2cMutationLabel::QueryPrelude,
                            0x10,
                            vec![I2cTransactionStep::WriteRead {
                                write_data: vec![0],
                                read_len: 1,
                            }],
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                    if reads == vec![vec![0xf5]] {
                        ready = true;
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                if !ready {
                    return Err("APW12 register-zero ready byte timed out".into());
                }
            }
            A::CheckHealth => self.check_health().await?,
            A::HashPower { enabled } => self.custody.hash_power(*enabled).await?,
            A::TerminalPowerOff => self.custody.terminal_power_off().await?,
            A::ChainReset { chain, asserted } => {
                self.chain(*chain)?;
                self.custody.chain_reset(*chain, *asserted).await?;
            }
            A::I2c(exchange) => {
                return execute_framed(&self.i2c, &self.pic, exchange)
                    .await
                    .map(Bm1398RuntimeReply::Bytes)
            }
            A::Asic { chain, operation } => {
                let commands = self.chain(*chain)?.commands.clone();
                let operation = operation.clone();
                tokio::task::spawn_blocking(move || execute_asic(commands.as_ref(), operation))
                    .await
                    .map_err(|e| e.to_string())??;
            }
            A::ReadMiscControl { chain } => {
                self.check_health().await?;
                let commands = self.chain(*chain)?.commands.clone();
                let value = tokio::task::spawn_blocking(move || {
                    commands
                        .send_read_reg_bm1397plus(0, 0x18)
                        .map_err(|e| e.to_string())?;
                    let mut body = [0_u8; 7];
                    let length = commands
                        .read_response_frame(&mut body, 1000)
                        .map_err(|e| e.to_string())?;
                    let body = body
                        .get(..length)
                        .ok_or("oversized BM1398 register reply")?;
                    misc_control_reply(body)
                })
                .await
                .map_err(|e| e.to_string())??;
                return Ok(Bm1398RuntimeReply::RegisterValue(value));
            }
            A::ReadChipAddresses { chain, timeout_ms } => {
                let commands = self.chain(*chain)?.commands.clone();
                let population_cap = usize::from(self.board.chips_per_chain());
                let timeout = u64::from((*timeout_ms).min(30_000));
                let (replies, chip_zero) = tokio::task::spawn_blocking(move || {
                    let deadline = Instant::now() + Duration::from_millis(timeout);
                    let mut replies = Vec::new();
                    let mut chip_zero = None;
                    while Instant::now() < deadline {
                        let mut body = [0u8; 7];
                        let remaining = deadline
                            .saturating_duration_since(Instant::now())
                            .as_millis() as u64;
                        let n = commands
                            .read_response_frame(&mut body, remaining.max(1))
                            .map_err(|e| e.to_string())?;
                        if n == 0 {
                            break;
                        }
                        if replies.len() >= population_cap {
                            return Err(format!(
                                "more than {population_cap} BM1398 replies"
                            ));
                        }
                        let reply = assigned_chip_address(&body[..n])?;
                        if reply.0 == 0 {
                            chip_zero = dcentrald_api_types::bm1398_get_address::parse_bm1398_get_address_body(&body[..n]).ok();
                        }
                        replies.push(reply);
                    }
                    Ok::<_, String>((replies, chip_zero))
                })
                .await
                .map_err(|e| e.to_string())??;
                let raw = self
                    .factory_pages
                    .get(chain)
                    .ok_or("factory page was not observed on this chain")?;
                if observed_protocol_from_bm1398_factory_page(
                    raw,
                    self.board.stock_board_name(),
                    chip_zero,
                ) != Some(dcentrald_common::AsicProtocolIdentity::Bm1398)
                {
                    return Err("factory page and actual BM1398 chip response did not join".into());
                }
                return Ok(Bm1398RuntimeReply::ChipAddresses(replies));
            }
            A::ConfigureWork {
                chain,
                mode,
                work_interval,
                ..
            } => {
                self.check_health().await?;
                let config = fpga::Bm1398FpgaWorkConfig::new(*mode, *work_interval)?;
                config.apply(&self.chain(*chain)?.fifo)?;
                self.configured.insert(*chain, config.word_count());
            }
            A::Work { chain, words } => {
                if self.configured.get(chain).copied() != Some(words.len()) {
                    return Err("FIFO width not configured".into());
                }
                self.check_health().await?;
                let fifo = &self.chain(*chain)?.fifo;
                if !fpga::whole_frame_capacity(fifo, words.len())? {
                    return Err("BM1398 work FIFO has no complete packet capacity".into());
                }
                fifo.write_work(words);
            }
            A::StopWork => {
                self.configured.clear(); /* rail is already off; never zero CTRL */
            }
            A::StopCustody => {
                self.cancel.cancel();
                if let Some(watcher) = self.watcher.take() {
                    watcher.await.map_err(|e| e.to_string())??;
                }
            }
            A::DelayMs(ms) => tokio::time::sleep(Duration::from_millis(u64::from(*ms))).await,
        }
        Ok(Bm1398RuntimeReply::Complete)
    }
}

fn execute_asic(backend: &dyn Bm1397PlusChainBackend, op: TransportOp) -> Result<(), String> {
    let result = match op {
        TransportOp::SetBaudRate { baud } => backend.set_baud_rate(baud),
        TransportOp::SetResponseBodyLen { body_len } => backend.set_response_body_len(body_len),
        TransportOp::SendGetAddressBm1397Plus => backend.send_get_address_bm1397plus(),
        TransportOp::SendChainInactiveBm1397Plus => backend.send_chain_inactive_bm1397plus(),
        TransportOp::SendSetAddressBm1397Plus { addr } => backend.send_set_address_bm1397plus(addr),
        TransportOp::SendWriteRegBroadcastBm1397Plus { reg, value } => {
            backend.send_write_reg_broadcast_bm1397plus(reg, value)
        }
        TransportOp::SendWriteRegBm1397Plus {
            chip_addr,
            reg,
            value,
        } => backend.send_write_reg_bm1397plus(chip_addr, reg, value),
        TransportOp::SendReadRegBm1397Plus { chip_addr, reg } => {
            backend.send_read_reg_bm1397plus(chip_addr, reg)
        }
        TransportOp::SendWorkFrame { .. } => {
            return Err("BM1398 work must use the configured FIFO route".into())
        }
        TransportOp::DelayMs { ms } => {
            std::thread::sleep(Duration::from_millis(u64::from(ms)));
            Ok(())
        }
    };
    result.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn misc_control_read_requires_complete_crc_checked_exact_register_reply() {
        let mut body = [0, 0, 0x7a, 0x31, 0, 0x18, 0];
        body[6] = dcentrald_common::s19k_bm1366_uart_rx::command_response_crc5(&body[..6]);
        assert_eq!(misc_control_reply(&body).unwrap(), 0x0000_7a31);
        for size in 0..7 {
            assert!(misc_control_reply(&body[..size]).is_err());
        }
        for offset in 0..7 {
            let mut corrupt = body;
            corrupt[offset] ^= 1;
            assert!(misc_control_reply(&corrupt).is_err());
        }
        for (address, reg) in [(3, 0x18), (0, 0), (0, 0x68)] {
            let mut wrong = body;
            wrong[4] = address;
            wrong[5] = reg;
            wrong[6] = dcentrald_common::s19k_bm1366_uart_rx::command_response_crc5(&wrong[..6]);
            assert!(misc_control_reply(&wrong).is_err());
        }
    }

    #[cfg(feature = "sim-hal")]
    mod parser_flush {
        use super::*;
        use crate::i2c::{spawn_sim_i2c_service, I2cSimBackend};
        use std::collections::VecDeque;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct NackBackend {
            id: usize,
            writes: Mutex<Vec<(u8, u8)>>,
            replies: Mutex<VecDeque<u8>>,
            nack: tokio::sync::Notify,
        }
        impl NackBackend {
            fn new(replies: &[u8]) -> Arc<Self> {
                static NEXT: AtomicUsize = AtomicUsize::new(0x1398_0000);
                Arc::new(Self {
                    id: NEXT.fetch_add(1, Ordering::Relaxed),
                    writes: Mutex::new(Vec::new()),
                    replies: Mutex::new(replies.iter().copied().collect()),
                    nack: tokio::sync::Notify::new(),
                })
            }
        }
        impl I2cSimBackend for NackBackend {
            fn write(&self, bus: u8, addr: u8, data: &[u8]) -> crate::Result<usize> {
                assert_eq!(data.len(), 1, "PIC parser bytes need separate I2C writes");
                assert!(
                    (0x20..=0x22).contains(&addr),
                    "PIC recovery touched another endpoint"
                );
                let failed = {
                    let mut writes = self.writes.lock().unwrap();
                    writes.push((addr, data[0]));
                    writes.len() == 3
                };
                if failed {
                    self.nack.notify_one();
                    // Let another caller queue while the first wire operation
                    // is incomplete. The PIC lane must retain its flush order.
                    std::thread::sleep(Duration::from_millis(50));
                    return Err(crate::HalError::I2c {
                        bus,
                        addr,
                        detail: "injected PIC NACK".into(),
                    });
                }
                Ok(1)
            }
            fn read(&self, _: u8, _: u8, buf: &mut [u8]) -> crate::Result<usize> {
                assert_eq!(buf.len(), 1);
                buf[0] = self
                    .replies
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected PIC read");
                Ok(1)
            }
            fn write_read(&self, _: u8, _: u8, _: &[u8], _: &mut [u8]) -> crate::Result<()> {
                panic!("PIC recovery used an EEPROM/APW transaction")
            }
            fn service_identity(&self) -> Option<usize> {
                Some(self.id)
            }
        }

        #[tokio::test]
        async fn pic_nack_flushes_before_waiting_thermal_request_and_preserves_failure() {
            let thermal_reply = [0x3b, 1, 7, 0x3c, 1, 50, 0x80, 0, 0xf6];
            let backend = NackBackend::new(&thermal_reply);
            let worker =
                spawn_sim_i2c_service(0, backend.clone(), (0x50..=0x57).collect()).unwrap();
            let pic = Nbp1901PicService::new(worker.clone()).unwrap();
            let first = pic.clone();
            let failed = tokio::spawn(async move { first.read_version(0).await });
            backend.nack.notified().await;
            let next = pic.clone();
            let thermal = tokio::spawn(async move { next.read_temperature(1, 0x48).await });
            assert!(failed
                .await
                .unwrap()
                .unwrap_err()
                .contains("injected PIC NACK"));
            assert_eq!(thermal.await.unwrap().unwrap(), thermal_reply);
            let mut expected: Vec<_> = [0x55, 0xaa, 4].into_iter().map(|b| (0x20, b)).collect();
            expected.extend(std::iter::repeat_n((0x20, 0), 16));
            expected.extend(
                [
                    0x55, 0xaa, 6, 0x3b, 0x48, 0, 0, 0x89, 0x55, 0xaa, 6, 0x3c, 0x48, 2, 0, 0x8c,
                ]
                .into_iter()
                .map(|b| (0x21, b)),
            );
            assert_eq!(*backend.writes.lock().unwrap(), expected);
            assert!(pic.read_version(3).await.is_err());
            assert!(pic.read_temperature(1, 0x50).await.is_err());
            assert!(worker
                .transaction_mutating(
                    I2cMutationLabel::QueryPrelude,
                    0x50,
                    vec![I2cTransactionStep::Write(vec![0])]
                )
                .is_err());
            assert_eq!(*backend.writes.lock().unwrap(), expected);
        }

        #[tokio::test]
        async fn cancelled_pic_caller_retains_parser_flush_before_next_command() {
            let backend = NackBackend::new(&[5, 0x17, 0x89, 0, 0xa5]);
            let worker =
                spawn_sim_i2c_service(0, backend.clone(), (0x50..=0x57).collect()).unwrap();
            let pic = Nbp1901PicService::new(worker).unwrap();
            let first = pic.clone();
            let cancelled = tokio::spawn(async move { first.read_version(0).await });
            backend.nack.notified().await;
            cancelled.abort();
            assert!(cancelled.await.unwrap_err().is_cancelled());
            assert_eq!(pic.read_version(1).await.unwrap(), [5, 0x17, 0x89, 0, 0xa5]);
            let writes = backend.writes.lock().unwrap();
            assert_eq!(writes.len(), 3 + 16 + 6);
            assert_eq!(&writes[3..19], &[(0x20, 0); 16]);
            assert!(writes[19..].iter().all(|(address, _)| *address == 0x21));
        }
    }

    #[test]
    fn stock_pic_and_apw_use_distinct_atomic_worker_dialects() {
        let (label, addr, steps) = stock_framed_transaction(&Bm1398FramedExchange {
            endpoint: Bm1398FramedEndpoint::Pic { chain: 2 },
            request: vec![0x55, 0xaa, 4, 0x17, 0, 0x1b],
            response_bytes: 5,
        })
        .unwrap();
        assert_eq!(label, I2cMutationLabel::QueryPrelude);
        assert_eq!(addr, 0x22);
        assert!(
            matches!(&steps[0], I2cTransactionStep::WriteByteByByte(v) if v == &[0x55, 0xaa, 4, 0x17, 0, 0x1b])
        );
        assert!(matches!(steps[1], I2cTransactionStep::SleepMs(300)));
        assert_eq!(steps.len(), 7);
        let (_, addr, steps) = stock_framed_transaction(&Bm1398FramedExchange {
            endpoint: Bm1398FramedEndpoint::Apw12,
            request: vec![0x55, 0xaa, 4, 2, 6, 0],
            response_bytes: 8,
        })
        .unwrap();
        assert_eq!(addr, 0x10);
        assert!(matches!(&steps[0], I2cTransactionStep::Write(v) if v == &[0x11, 0x55]));
        assert!(
            matches!(&steps[7], I2cTransactionStep::WriteRead { write_data, read_len: 1 } if write_data == &[0x11])
        );
        assert!(matches!(
            steps.last(),
            Some(I2cTransactionStep::SleepMs(100))
        ));
    }

    #[test]
    fn assigned_reply_uses_register_value_and_rejects_nonce_crc_or_wrong_family() {
        assert_eq!(
            assigned_chip_address(&[0x13, 0x98, 0x18, 0, 0, 0, 4]).unwrap(),
            (0, 0x1398)
        );
        for addr in (2..=226).step_by(2) {
            let mut body = [0x13, 0x98, 0x18, addr, addr, 0, 0];
            body[6] = dcentrald_common::s19k_bm1366_uart_rx::command_response_crc5(&body[..6]);
            assert_eq!(assigned_chip_address(&body).unwrap(), (addr, 0x1398));
            body[6] |= 0x80;
            assert!(assigned_chip_address(&body).is_err());
        }
        assert!(assigned_chip_address(&[0x13, 0x97, 0x18, 0, 0, 0, 6]).is_err());
    }
}
