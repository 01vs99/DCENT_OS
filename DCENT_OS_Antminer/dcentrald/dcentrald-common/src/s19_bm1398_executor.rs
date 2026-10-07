//! Executable BM1398 (NBP1901/NBS1902/NBT1903/BHB28611) startup, work
//! and shutdown through one hardware owner.
//!
//! Wire source: HashSource/bmminer_NBP1901_analysis, stock SHA-256
//! e91e6d9fa7b8524abdb05ac5ca4b7118c6f50a58b6075541139c6f56c1b21d14.
//! PIC: 46178 version, 4672c enable, 46900 disable, 46acc heartbeat.
//! APW: 48520 exchange, 48910 version, 48834 rail-code, 48d38 DAC law.
//! topol.conf binds NBP1901, PIC1704, GPIO907 and 114 chips at interval 2;
//! each other model's own topol.conf binds its geometry and endpoints.
//! The actual stock binaries retain the PIC version constructor at NBS/NBP
//! 0x45a6c, NBT0x46244 and S19a0x465fc; PLL search/field packing and both
//! core writes were checked in those binaries too. These are software
//! interoperability observations, never live captures or EEPROM identities.
//! This executor never writes EEPROM or sends PIC RESET/JUMP/flash commands.
//! Physical power/reset semantics and periodic thermal/heartbeat custody remain
//! the platform adapter's responsibility; success requires actual acknowledgements.

use super::{Bm1398FpgaMidstateMode, Bm1398HybridDeskPlan};
use crate::serial_chain_proof::ChainCoverageCertificate;
use crate::TransportOp;
use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bm1398RuntimeAction {
    /// Read-only exact-name observation. Unnamed legacy11/42 pages cannot
    /// acquire an image-selected model name or a sibling BHB prefix identity.
    VerifyFactoryIdentity {
        chain: u8,
    },
    /// Must acquire single-owner thermal, cooling and independent power-cut
    /// custody. PIC heartbeats are added only after their dialect is verified.
    StartCustody {
        chains: Vec<u8>,
    },
    /// Add the exact, now-verified framed PIC to the same worker's periodic
    /// heartbeat schedule. No parallel I2C handle may be opened.
    MaintainPicHeartbeat {
        chain: u8,
    },
    /// Stock 48910 probes PSU register 0 for 0xf5, at most 10 times, 100 ms
    /// apart, before the version query. No command-table fallback.
    WaitPsuReady,
    CheckHealth,
    /// Board-scoped GPIO907: false = write 1 (OFF), true = write 0 (ON).
    HashPower {
        enabled: bool,
    },
    /// Permanent power cut and energization fence for this owner generation.
    /// Distinct from the temporary OFF state used during prepared startup.
    TerminalPowerOff,
    /// Hash-chain reset only; never a PIC RESET command.
    ChainReset {
        chain: u8,
        asserted: bool,
    },
    /// A complete framed exchange, serialized by the existing I2C worker.
    I2c(Bm1398FramedExchange),
    Asic {
        chain: u8,
        operation: TransportOp,
    },
    /// Correlated, CRC-checked register-zero replies within a bounded window.
    ReadChipAddresses {
        chain: u8,
        timeout_ms: u32,
    },
    /// Address-zero register0x18, CRC checked by the retained command owner.
    ReadMiscControl {
        chain: u8,
    },
    /// Use the existing BM1398 codec and exact Braiins FPGA FIFO composition;
    /// configure response length, midstate mode and work time together.
    ConfigureWork {
        chain: u8,
        frequency_mhz: u16,
        mode: Bm1398FpgaMidstateMode,
        work_interval: Duration,
    },
    /// Caller-encoded BM1398 FPGA words; job-ring ownership stays with caller.
    Work {
        chain: u8,
        words: Vec<u32>,
    },
    StopWork,
    StopCustody,
    DelayMs(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1398FramedExchange {
    pub endpoint: Bm1398FramedEndpoint,
    pub request: Vec<u8>,
    pub response_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398FramedEndpoint {
    /// PIC chain address 0x20+chain, raw bytes, 300 ms before read (46178 etc.).
    Pic { chain: u8 },
    /// PSU 0x10: each byte through register 0x11, 400 ms before read and
    /// 100 ms after read (48520). Not an SMBus command-table transaction.
    Apw12,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bm1398RuntimeReply {
    Complete,
    Bytes(Vec<u8>),
    /// Decoder must reject CRC/unknown generation; serial is retained rather
    /// than assumed unique (two Sep 2 physical boards share the same serial).
    FactoryIdentity {
        /// Observed name, never the name selected by the image. Older factory
        /// pages legitimately carry no name and cannot prove an exact SKU.
        stock_board_name: Option<String>,
        serial: String,
    },
    ChipAddresses(Vec<(u8, u16)>),
    RegisterValue(u32),
}

/// One daemon-owned adapter executes every action. No default methods exist:
/// an unimplemented hardware operation cannot accidentally report success.
pub trait Bm1398RuntimeIo {
    fn execute(
        &mut self,
        action: &Bm1398RuntimeAction,
    ) -> impl Future<Output = Result<Bm1398RuntimeReply, String>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1398RuntimeFailure {
    pub detail: String,
    /// Shutdown errors never replace the initiating fault.
    pub shutdown_errors: Vec<String>,
}

impl std::fmt::Display for Bm1398RuntimeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; shutdown errors: {:?}",
            self.detail, self.shutdown_errors
        )
    }
}
impl std::error::Error for Bm1398RuntimeFailure {}

/// Explicit caller-selected point within one bin's production stock ladder
/// (NBP1901: 500/525 MHz and 12.60/12.80/13.00 V; NBS1902: 650/675 MHz and
/// 13.80/14.00/14.20 V; NBT1903: 550-625 MHz and 14.00/14.20/14.40 V — each
/// bin's exact levels.json rows, enforced as pairs by [`Self::validate`]).
/// Factory EEPROM V/F is never automatically applied. Startup uses the same
/// rail; a need for a higher cold-start rail is a distinct operating policy,
/// not a hidden fallback.
#[derive(Debug, Clone)]
pub struct Bm1398RuntimeConfig {
    pub plan: Bm1398HybridDeskPlan,
    pub active_chains: Vec<u8>,
    pub frequency_mhz: u16,
    pub voltage_cv: u16,
}

impl Bm1398RuntimeConfig {
    /// Initial scheduler policy retained from DCENT's BM1398 dispatcher.
    /// This is not a claim that the vendor uses the same nonce geometry or
    /// the same 0.9 margin. The adapter independently applies the recovered
    /// vendor register conversion (100 MHz, capped at 50 ms).
    pub fn work_interval(&self) -> Duration {
        let midstates = match self.plan.midstate_mode {
            Bm1398FpgaMidstateMode::Four => 4_u64,
            Bm1398FpgaMidstateMode::Eight => 8,
        };
        // Preserve the previous integer tick truncation, then express the
        // scheduler decision as a duration rather than a register address.
        let ticks = 90 * midstates * 524_288 / u64::from(self.frequency_mhz).max(1);
        Duration::from_nanos(ticks.max(1) * 10)
    }

    fn validate(&self) -> Result<(), String> {
        // Per-bin stock geometry: the 76-chip rows are the first-party
        // NBS1902/NBT1903 topol.conf pins (Phase A §3.7 rows 7/9); the
        // 114/2 row is the RE'd NBP1901 composition.
        let geometry_ok = self.plan.chips_per_chain == self.plan.model.chips_per_chain()
            && self.plan.address_interval == self.plan.model.address_interval();
        if !geometry_ok
            || self.plan.chains != 3
            || self.plan.work_id_slots
                != match self.plan.midstate_mode {
                    Bm1398FpgaMidstateMode::Four => 16_384,
                    Bm1398FpgaMidstateMode::Eight => 8_192,
                }
            || self.active_chains.is_empty()
            || self.active_chains.len() > 3
            || self.active_chains.iter().any(|&chain| chain >= 3)
            || self
                .active_chains
                .iter()
                .enumerate()
                .any(|(i, c)| self.active_chains[..i].contains(c))
        {
            return Err(
                "BM1398 native runtime requires unique chain slots 0..2 and the exact stock bin geometry"
                    .into(),
            );
        }
        // The (frequency, rail) pair must be a row of the bin's own held
        // stock levels.json ladder — per-platform bounds, never a family-wide
        // union.
        if !self
            .plan
            .model
            .stock_levels()
            .contains(&(self.frequency_mhz, self.voltage_cv))
        {
            return Err(
                "requested operating point is outside the stock ladder of this BM1398 bin"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398RuntimeState {
    Prepared,
    Starting,
    Ready,
    Stopped,
    Faulted,
}

/// The lifecycle owns its transport for its whole lifetime, including teardown.
/// The surrounding daemon must call shutdown on cancellation; the adapter's
/// independent custody must also cut power if this future is dropped.
pub struct Bm1398Runtime<T: Bm1398RuntimeIo> {
    io: T,
    config: Bm1398RuntimeConfig,
    state: Bm1398RuntimeState,
    verified_pic_chains: Vec<u8>,
    coverage: BTreeMap<u8, ChainCoverageCertificate>,
}

impl<T: Bm1398RuntimeIo> Bm1398Runtime<T> {
    pub fn new(board_target: &str, config: Bm1398RuntimeConfig, io: T) -> Result<Self, String> {
        if board_target != config.plan.model.board_target() {
            return Err(format!(
                "exact {} carrier required",
                config.plan.model.board_target()
            ));
        }
        config.validate()?;
        Ok(Self {
            io,
            config,
            state: Bm1398RuntimeState::Prepared,
            verified_pic_chains: vec![],
            coverage: BTreeMap::new(),
        })
    }

    pub fn state(&self) -> Bm1398RuntimeState {
        self.state
    }

    /// Read-only access for the platform's nonce FIFO poller. Mutation and
    /// work submission remain owned by this lifecycle.
    pub fn transport(&self) -> &T {
        &self.io
    }

    async fn complete(&mut self, action: Bm1398RuntimeAction) -> Result<(), String> {
        match self.io.execute(&action).await? {
            Bm1398RuntimeReply::Complete => Ok(()),
            _ => Err(format!("unexpected acknowledgement for {action:?}")),
        }
    }

    async fn exchange(
        &mut self,
        endpoint: Bm1398FramedEndpoint,
        request: Vec<u8>,
        response_bytes: usize,
    ) -> Result<Vec<u8>, String> {
        let action = Bm1398RuntimeAction::I2c(Bm1398FramedExchange {
            endpoint,
            request,
            response_bytes,
        });
        match self.io.execute(&action).await? {
            Bm1398RuntimeReply::Bytes(bytes) if bytes.len() == response_bytes => Ok(bytes),
            _ => Err("framed controller response has wrong type or length".into()),
        }
    }

    async fn pic_enable(&mut self, chain: u8, enabled: bool) -> Result<(), String> {
        let value = u8::from(enabled);
        let reply = self
            .exchange(
                Bm1398FramedEndpoint::Pic { chain },
                vec![0x55, 0xaa, 5, 0x15, value, 0, 0x1a + value],
                2,
            )
            .await?;
        if reply != [0x15, 1] {
            return Err("PIC1704 enable/disable was not acknowledged".into());
        }
        Ok(())
    }

    async fn heartbeat(&mut self, chain: u8) -> Result<(), String> {
        let reply = self
            .exchange(
                Bm1398FramedEndpoint::Pic { chain },
                vec![0x55, 0xaa, 4, 0x16, 0, 0x1a],
                6,
            )
            .await?;
        // Exact stock 46acc checks command and success at bytes 1/2. Do not
        // impose the APW response preamble/checksum grammar on this dialect.
        if reply[1] != 0x16 || reply[2] != 1 {
            return Err("PIC1704 heartbeat failed".into());
        }
        Ok(())
    }

    async fn asic(&mut self, chain: u8, operation: TransportOp) -> Result<(), String> {
        self.complete(Bm1398RuntimeAction::Asic { chain, operation })
            .await
    }

    async fn write_reg(&mut self, chain: u8, reg: u8, value: u32) -> Result<(), String> {
        self.asic(
            chain,
            TransportOp::SendWriteRegBroadcastBm1397Plus { reg, value },
        )
        .await
    }

    pub async fn start(&mut self) -> Result<(), Bm1398RuntimeFailure> {
        if self.state != Bm1398RuntimeState::Prepared {
            return Err(Bm1398RuntimeFailure {
                detail: "runtime is not prepared".into(),
                shutdown_errors: vec![],
            });
        }
        self.state = Bm1398RuntimeState::Starting;
        if let Err(detail) = self.start_inner().await {
            let shutdown_errors = self.cut_power_and_stop().await;
            self.state = Bm1398RuntimeState::Faulted;
            return Err(Bm1398RuntimeFailure {
                detail,
                shutdown_errors,
            });
        }
        self.state = Bm1398RuntimeState::Ready;
        Ok(())
    }

    async fn start_inner(&mut self) -> Result<(), String> {
        let chains = self.config.active_chains.clone();
        // Establish independent power-cut/thermal custody before any work or
        // energization; cut first, then perform passive identity/dialect reads.
        self.complete(Bm1398RuntimeAction::StartCustody {
            chains: chains.clone(),
        })
        .await?;
        self.complete(Bm1398RuntimeAction::HashPower { enabled: false })
            .await?;
        self.complete(Bm1398RuntimeAction::CheckHealth).await?;
        for &chain in &chains {
            self.complete(Bm1398RuntimeAction::ChainReset {
                chain,
                asserted: true,
            })
            .await?;
            match self
                .io
                .execute(&Bm1398RuntimeAction::VerifyFactoryIdentity { chain })
                .await?
            {
                Bm1398RuntimeReply::FactoryIdentity {
                    stock_board_name,
                    serial,
                } if stock_board_name.as_deref().is_some_and(|name| {
                    self.config.plan.model.stock_board_names().contains(&name)
                }) && !serial.is_empty() => {}
                _ => {
                    return Err(format!(
                        "chain {chain} lacks decoded {} factory identity",
                        self.config.plan.model.stock_board_names()[0]
                    ))
                }
            }
            let reply = self
                .exchange(
                    Bm1398FramedEndpoint::Pic { chain },
                    vec![0x55, 0xaa, 4, 0x17, 0, 0x1b],
                    5,
                )
                .await?;
            // 46178: length, opcode, fw, additive checksum BIG endian.
            let checksum = u16::from(reply[2]) + 0x1c;
            if reply[0] != 5
                || reply[1] != 0x17
                || reply[2] != 0x89
                || reply[3..] != checksum.to_be_bytes()
            {
                return Err(format!(
                    "chain {chain} is not the stock framed PIC1704 app 0x89"
                ));
            }
            self.verified_pic_chains.push(chain);
            self.pic_enable(chain, false).await?;
            self.complete(Bm1398RuntimeAction::MaintainPicHeartbeat { chain })
                .await?;
        }
        self.complete(Bm1398RuntimeAction::WaitPsuReady).await?;
        let reply = self
            .exchange(Bm1398FramedEndpoint::Apw12, vec![0x55, 0xaa, 4, 2, 6, 0], 8)
            .await?;
        validate_apw_reply(&reply, 2)?;
        if reply[4..6] != [0x71, 0] {
            return Err("PSU is not APW121215a stock framed 0x71".into());
        }
        // Five acknowledged ticks before any rail set; the custody worker
        // continues these during long enumeration and while work is running.
        for _ in 0..5 {
            for &chain in &chains {
                self.heartbeat(chain).await?;
            }
            self.complete(Bm1398RuntimeAction::DelayMs(1000)).await?;
            self.complete(Bm1398RuntimeAction::CheckHealth).await?;
        }
        let code = apw12_stock71_rail_code(self.config.voltage_cv)?;
        let checksum = u16::from(code) + 0x89;
        let reply = self
            .exchange(
                Bm1398FramedEndpoint::Apw12,
                vec![
                    0x55,
                    0xaa,
                    6,
                    0x83,
                    code,
                    0,
                    checksum as u8,
                    (checksum >> 8) as u8,
                ],
                8,
            )
            .await?;
        validate_apw_reply(&reply, 0x83)?;
        self.complete(Bm1398RuntimeAction::HashPower { enabled: true })
            .await?;
        for &chain in &chains {
            self.pic_enable(chain, true).await?;
            self.complete(Bm1398RuntimeAction::ChainReset {
                chain,
                asserted: false,
            })
            .await?;
            self.asic(chain, TransportOp::SetResponseBodyLen { body_len: 7 })
                .await?;
            self.asic(chain, TransportOp::SetBaudRate { baud: 115_200 })
                .await?;
            self.write_reg(chain, 0x54, 3).await?;
            self.asic(chain, TransportOp::SendChainInactiveBm1397Plus)
                .await?;
            let settle_ms = self
                .config
                .plan
                .enumeration
                .settle_delay()
                .as_millis()
                .min(u128::from(u32::MAX)) as u32;
            self.complete(Bm1398RuntimeAction::DelayMs(settle_ms))
                .await?;
            for addr in self.config.plan.expected_addresses() {
                self.asic(chain, TransportOp::SendSetAddressBm1397Plus { addr })
                    .await?;
                let ms = self
                    .config
                    .plan
                    .enumeration
                    .step_delay()
                    .as_millis()
                    .min(u128::from(u32::MAX)) as u32;
                self.complete(Bm1398RuntimeAction::DelayMs(ms.max(1)))
                    .await?;
            }
            self.complete(Bm1398RuntimeAction::DelayMs(settle_ms))
                .await?;
            self.asic(chain, TransportOp::SendGetAddressBm1397Plus)
                .await?;
            let timeout_ms = self
                .config
                .plan
                .enumeration
                .response_window()
                .as_millis()
                .min(u128::from(u32::MAX)) as u32;
            let replies = match self
                .io
                .execute(&Bm1398RuntimeAction::ReadChipAddresses { chain, timeout_ms })
                .await?
            {
                Bm1398RuntimeReply::ChipAddresses(replies) => replies,
                _ => return Err("missing CRC-checked chip-address window".into()),
            };
            if replies.iter().any(|(_, id)| *id != 0x1398) {
                return Err("non-BM1398 response in chain".into());
            }
            let addresses: Vec<u8> = replies.iter().map(|(address, _)| *address).collect();
            let coverage = self
                .config
                .plan
                .certify_chain(&addresses)
                .map_err(|e| e.to_string())?;
            self.coverage.insert(chain, coverage);
            // Adjacent core writes and frequency precede the final baud/ticket
            // writes, matching BM1398_CHAIN_INIT_STEPS (jig 1d124).
            self.write_reg(chain, 0x3c, 0x8000_8710).await?;
            self.write_reg(chain, 0x3c, 0x8000_8050).await?;
            self.write_reg(chain, 0x08, 0).await?;
            let (pll, _) = crate::resolve_bm1398_pll(self.config.frequency_mhz)
                .ok_or("BM1398 PLL point cannot be encoded")?;
            self.write_reg(chain, 0x08, pll.register_value).await?;
            // Work-format setup applies the carrier's startup baud. Finish
            // it before the ASIC/host transition so it cannot reset the host
            // to 115200 after the ASIC has moved to its working clock.
            self.complete(Bm1398RuntimeAction::ConfigureWork {
                chain,
                frequency_mhz: self.config.frequency_mhz,
                mode: self.config.plan.midstate_mode,
                work_interval: self.config.work_interval(),
            })
            .await?;
            let previous = match self
                .io
                .execute(&Bm1398RuntimeAction::ReadMiscControl { chain })
                .await?
            {
                Bm1398RuntimeReply::RegisterValue(value) => value,
                _ => return Err("missing CRC-checked BM1398 MiscControl observation".into()),
            };
            let baud = super::BM1398_RUNTIME_WORK_BAUD;
            let value = super::bm1398_oscillator_baud_register(previous, baud)?;
            self.write_reg(chain, 0x18, value).await?;
            // Stock 4ffe8 gives the ASIC50ms before changing the host divider.
            self.complete(Bm1398RuntimeAction::DelayMs(50)).await?;
            self.asic(chain, TransportOp::SetBaudRate { baud }).await?;
            match self
                .io
                .execute(&Bm1398RuntimeAction::ReadMiscControl { chain })
                .await?
            {
                Bm1398RuntimeReply::RegisterValue(observed) if observed == value => {}
                _ => return Err("BM1398 baud transition register readback mismatch".into()),
            }
            self.write_reg(chain, 0x14, 0).await?;
            self.complete(Bm1398RuntimeAction::CheckHealth).await?;
        }
        Ok(())
    }

    /// Work is unavailable until every selected chain has exact coverage and
    /// all startup transactions succeeded. A transport or health error cuts
    /// hash power before other teardown and permanently faults this instance.
    pub async fn submit_work(
        &mut self,
        chain: u8,
        words: &[u32],
    ) -> Result<(), Bm1398RuntimeFailure> {
        let count = match self.config.plan.midstate_mode {
            Bm1398FpgaMidstateMode::Four => 36,
            Bm1398FpgaMidstateMode::Eight => 68,
        };
        let midstate_mask = match self.config.plan.midstate_mode {
            Bm1398FpgaMidstateMode::Four => 3,
            Bm1398FpgaMidstateMode::Eight => 7,
        };
        if self.state != Bm1398RuntimeState::Ready
            || !self.coverage.contains_key(&chain)
            || words.len() != count
            || words[0] > u32::from(u16::MAX)
            || words[0] & midstate_mask != 0
        {
            return Err(Bm1398RuntimeFailure {
                detail: "work state/chain/FPGA frame width mismatch".into(),
                shutdown_errors: vec![],
            });
        }
        let result = async {
            self.complete(Bm1398RuntimeAction::CheckHealth).await?;
            self.complete(Bm1398RuntimeAction::Work {
                chain,
                words: words.to_vec(),
            })
            .await
        }
        .await;
        if let Err(detail) = result {
            let shutdown_errors = self.cut_power_and_stop().await;
            self.state = Bm1398RuntimeState::Faulted;
            return Err(Bm1398RuntimeFailure {
                detail,
                shutdown_errors,
            });
        }
        Ok(())
    }

    async fn cut_power_and_stop(&mut self) -> Vec<String> {
        let mut errors = Vec::new();
        for action in [
            Bm1398RuntimeAction::TerminalPowerOff,
            Bm1398RuntimeAction::StopWork,
        ] {
            if let Err(e) = self.complete(action).await {
                errors.push(e);
            }
        }
        for chain in self.verified_pic_chains.clone() {
            if let Err(e) = self.pic_enable(chain, false).await {
                errors.push(e);
            }
            if let Err(e) = self
                .complete(Bm1398RuntimeAction::ChainReset {
                    chain,
                    asserted: true,
                })
                .await
            {
                errors.push(e);
            }
        }
        // Keep independent custody alive when any power-cut step failed.
        if errors.is_empty() {
            if let Err(e) = self.complete(Bm1398RuntimeAction::StopCustody).await {
                errors.push(e);
            }
        }
        errors
    }

    pub async fn shutdown(&mut self) -> Result<(), Bm1398RuntimeFailure> {
        if self.state == Bm1398RuntimeState::Stopped {
            return Ok(());
        }
        let shutdown_errors = self.cut_power_and_stop().await;
        self.state = if shutdown_errors.is_empty() {
            Bm1398RuntimeState::Stopped
        } else {
            Bm1398RuntimeState::Faulted
        };
        if shutdown_errors.is_empty() {
            Ok(())
        } else {
            Err(Bm1398RuntimeFailure {
                detail: "BM1398 shutdown was incomplete".into(),
                shutdown_errors,
            })
        }
    }
}

/// Exact stock 48d38 law for version 0x71; not the different .139 measured
/// transfer law in the legacy HAL. This function is deliberately stock-scoped:
/// only centivolt rails appearing in one of the held per-bin stock
/// levels.json ladders are accepted, and per-bin (frequency, rail) pair
/// membership is enforced by [`Bm1398RuntimeConfig::validate`]. The law was
/// recovered from the NBP1901 stock 0x71 build; applying it to the
/// NBS1902/NBT1903 bins at the same PSU version (both of their stock
/// topol.conf `power.version` lists include 67) is desk evidence, not a live
/// rail measurement.
pub fn apw12_stock71_rail_code(voltage_cv: u16) -> Result<u8, String> {
    // Union of NBP1901 {1260,1280,1300}, NBS1902 {1380,1400,1420} and
    // NBT1903 {1400,1420,1440} stock rail levels.
    const STOCK_RAIL_LEVELS_CV: [u16; 17] = [
        1240, 1250, 1260, 1270, 1280, 1290, 1300, 1310, 1320, 1330, 1340, 1350, 1360, 1380, 1400,
        1420, 1440,
    ];
    if !STOCK_RAIL_LEVELS_CV.contains(&voltage_cv) {
        return Err("outside the stock BM1398-family rail ladders".into());
    }
    let code = (1190.935_338 - f64::from(voltage_cv) / 100.0 * 78.742_588).trunc();
    if !(0.0..=255.0).contains(&code) {
        return Err("APW12 rail code overflow".into());
    }
    Ok(code as u8)
}

fn validate_apw_reply(reply: &[u8], command: u8) -> Result<(), String> {
    if reply.len() != 8 || reply[..2] != [0x55, 0xaa] || reply[2] != 6 || reply[3] != command {
        return Err("APW12 response preamble, length or command mismatch".into());
    }
    let checksum: u16 = reply[2..6].iter().map(|&byte| u16::from(byte)).sum();
    if reply[6..8] != checksum.to_le_bytes() {
        return Err("APW12 response checksum mismatch".into());
    }
    Ok(())
}
