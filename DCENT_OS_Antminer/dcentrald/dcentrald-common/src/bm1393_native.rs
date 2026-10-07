//! Native C43/BM1393 executor, independent of the stock kernel/DMA driver.
//!
//! Evidence: campaign r03 raw S9k ELF d09c482f… and both production S9 SE
//! ELFs. The work codec is independently replayed through original ARM and
//! Thumb instructions. The adapter must retain the loaded C43 fabric, PIC
//! worker and cooling/reset custody; a model label alone cannot supply them.

use std::collections::BTreeMap;
use std::future::Future;

use crate::s9se_eeprom;
use crate::s9se_enum::{S9SE_ADDR_INTERVAL, S9SE_ASSIGNMENT_SLOTS, S9SE_CHIPS_PER_CHAIN};
use crate::s9se_init::open_core_tw0;
use crate::s9se_nonce::{classify_return_record, S9SeFifoRecord};
use crate::s9se_pic;
use crate::s9se_pll::{
    pack_operational_pll_frames, pack_unused_pll_park_frames, FREQ_HIGH_PLL_1393, FREQ_PLL_1393,
};
use crate::s9se_regs;
use crate::s9se_timeout::{stock_timeout_s9se, timeout_control_word};
use crate::s9se_vil::{pack_chain_inactive_vil, pack_set_address_vil};
use crate::s9se_voltage::{power_iic_from_voltage_on_map, S9SeIicMap};
use crate::serial_chain_proof::ChainCoverageCertificate;

pub const BM1393_WORK_ID_SLOTS: usize = 32768;
/// At most eight frames per physical chain per scheduler turn.
pub const BM1393_MAX_WORK_BATCH: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1393TemperatureSite {
    pub chip_addr: u8,
    pub offset: i8,
}

/// CRC-bound production EEPROM interpretation. Construction is read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1393FactoryProfile {
    minor: u8,
    pcb: u8,
    bom: u8,
    voltage_mv: u16,
    preferred_sensor_device: u8,
    sites: Vec<Bm1393TemperatureSite>,
}

impl Bm1393FactoryProfile {
    pub fn decode(bytes: &[u8; 256]) -> Result<Self, String> {
        // array_check_crc@6d326 compares a native LE uint16 at bytes254..255.
        if !s9se_eeprom::admit_eeprom_crc(
            &bytes[..254],
            u16::from_le_bytes([bytes[254], bytes[255]]),
        ) {
            return Err("BM1393 protected factory EEPROM CRC mismatch".into());
        }
        s9se_eeprom::admit_major_is_1393(bytes[248])
            .map_err(|_| "factory EEPROM does not identify BM1393")?;
        let factory_mv = (u16::from(bytes[1]) + 300) * 20;
        // Production mode0 rejects <=8 V and >=10.5 V. Its configured stock
        // fallback is9.5 V; do not treat erased factory bytes as a raw DAC.
        let voltage_mv = if factory_mv > 8000 && factory_mv < 10500 {
            factory_mv
        } else {
            9500
        };
        // calibration_sensor_offset@16c6e: type6=TMP441B,7=TMP411C.
        let preferred_sensor_device = match bytes[121] {
            6 => 0x9a,
            7 => 0x9c,
            _ => 0x98,
        };
        let count = usize::from(bytes[122]);
        // is_tempsensor_data_correct@15776: only type1 uses EEPROM offsets,
        // 1..6 sites, positions1..60, absolute signed offset<=9.
        let factory_sites = bytes[121] == 1
            && (1..=6).contains(&count)
            && (0..count).all(|i| {
                (1..=60).contains(&bytes[123 + i * 2])
                    && i16::from(bytes[124 + i * 2] as i8).abs() <= 9
            });
        let sites = if factory_sites {
            let mut sites = Vec::with_capacity(count);
            for i in 0..count {
                let site = Bm1393TemperatureSite {
                    chip_addr: (bytes[123 + i * 2] - 1) * 4,
                    offset: bytes[124 + i * 2] as i8,
                };
                if sites
                    .iter()
                    .any(|s: &Bm1393TemperatureSite| s.chip_addr == site.chip_addr)
                {
                    return Err("duplicate BM1393 factory temperature site".into());
                }
                sites.push(site);
            }
            sites
        } else {
            // Stock fallback in calibration_sensor_offset: positions31,40,
            // offset-5; actual sensor identity is still queried before work.
            vec![
                Bm1393TemperatureSite {
                    chip_addr: 120,
                    offset: -5,
                },
                Bm1393TemperatureSite {
                    chip_addr: 156,
                    offset: -5,
                },
            ]
        };
        Ok(Self {
            minor: s9se_eeprom::chip_minor_from_byte(bytes[248]),
            pcb: bytes[252],
            bom: bytes[253],
            voltage_mv,
            preferred_sensor_device,
            sites,
        })
    }

    pub fn minor(&self) -> u8 {
        self.minor
    }
    pub fn pcb(&self) -> u8 {
        self.pcb
    }
    pub fn bom(&self) -> u8 {
        self.bom
    }
    pub fn voltage_mv(&self) -> u16 {
        self.voltage_mv
    }
    pub fn preferred_sensor_device(&self) -> u8 {
        self.preferred_sensor_device
    }
    pub fn sites(&self) -> &[Bm1393TemperatureSite] {
        &self.sites
    }
    pub fn rail_code(&self, millivolts: u16) -> Result<u8, String> {
        if !(8500..=9500).contains(&millivolts) || millivolts > self.voltage_mv {
            return Err(
                "BM1393 requested voltage exceeds conservative factory-bound beta range".into(),
            );
        }
        // get_power_iic_value_from_voltage@3b734/3b742: minor4 or2 primary.
        let map = if matches!(self.minor, 2 | 4) {
            S9SeIicMap::PrimaryCeBBgm
        } else {
            S9SeIicMap::Alternate
        };
        power_iic_from_voltage_on_map(f64::from(millivolts) / 1000.0, map)
            .map_err(|_| "invalid BM1393 rail map".into())
    }
}

/// The daemon supplies SHA256 midstate bytes and header bytes64..76 in the
/// same word order as the held production work object. No inline work time.
pub fn encode_bm1393_work(
    chain: u8,
    work_id: u16,
    data: &[u8; 12],
    midstate: &[u8; 32],
) -> Result<[u32; 13], String> {
    if chain > 15 || usize::from(work_id) >= BM1393_WORK_ID_SLOTS {
        return Err("BM1393 work identity out of range".into());
    }
    let mut words = [0; 13];
    // S9k31660..31880 and independent S9SE53be4..53d74; dummy open-core
    // uses a different first word and must not be reused for real work.
    words[0] = 0x0180_0000 | (u32::from(chain) << 16);
    words[1] = u32::from(work_id);
    for (dst, src) in words[2..5].iter_mut().zip(data.chunks_exact(4)) {
        *dst = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
    }
    for (dst, src) in words[5..].iter_mut().zip(midstate.chunks_exact(4)) {
        *dst = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
    }
    Ok(words)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bm1393Action {
    /// Verify current boot/load receipt and exact C43 version, retain exclusive
    /// MMIO+IIC ownership, start independent cut watcher and fresh fan/XADC.
    StartCustody {
        chains: Vec<u8>,
    },
    ReadProtectedEeprom {
        chain: u8,
    },
    ChainReset {
        chain: u8,
        asserted: bool,
    },
    Pic {
        chain: u8,
        command: Bm1393PicCommand,
    },
    MaintainPicHeartbeat {
        chain: u8,
    },
    /// Native adapter initializes raw-TW mode and default BC baud; no DMA.
    ConfigureFabric,
    SetBaud {
        divisor: u8,
    },
    Asic {
        chain: u8,
        bytes: Vec<u8>,
    },
    /// Flush stale records, issue register0 read-all, retain correlated
    /// CRC-clean replies and return observed physical addresses+chip IDs.
    ReadChipCoverage {
        chain: u8,
    },
    /// Reproduce stock misc I2C, query sensor manufacturer, configure extended
    /// range and factory offset, verify fresh readings before returning.
    ConfigureTemperature {
        chain: u8,
        profile: Bm1393FactoryProfile,
    },
    /// Check retained watcher, fresh tach/XADC and (once configured) all sites.
    CheckHealth,
    SetWorkTimeout {
        word: u32,
    },
    Work {
        chain: u8,
        words: [u32; 13],
    },
    /// Nonblocking FIFO submission. Each chain's accepted frames form a prefix.
    WorkBatch {
        items: Vec<(u8, [u32; 13])>,
    },
    /// Population remaining after checked reset and complete PIC-off replies.
    ReadActiveChains,
    /// Fence this chain before draining writes and checking its local cut.
    /// Failure requires whole-owner closeout; this never disarms custody.
    IsolateChain {
        chain: u8,
    },
    ReadReturns {
        maximum: u16,
    },
    StopWork,
    /// Called only after all selected reset assertions and PIC off ACKs.
    StopCustody,
    DelayMs(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1393PicCommand {
    Version,
    Heartbeat,
    Enable(bool),
    Voltage(u8),
}

impl Bm1393PicCommand {
    pub fn wire(self) -> Result<(Vec<u8>, usize), String> {
        Ok(match self {
            Self::Version => (s9se_pic::pack_get_software_version(), 5),
            Self::Heartbeat => (s9se_pic::pack_heartbeat(), 6),
            Self::Enable(enabled) => (s9se_pic::pack_enable_dc_dc(u8::from(enabled)), 2),
            Self::Voltage(code) => (
                s9se_pic::pack_set_voltage(code).map_err(|_| "BM1393 DAC bit7 must be clear")?,
                2,
            ),
        })
    }
    pub fn validate(self, reply: &[u8]) -> Result<(), String> {
        let valid = match self {
            Self::Version => {
                reply.len() == 5
                    && s9se_pic::admit_pic_reply_crc(reply)
                    && s9se_pic::admit_software_version_ack(reply)
                        .is_some_and(|v| v != 0 && v != 0xff && v != 0x86)
            }
            Self::Heartbeat => {
                reply.len() == 6
                    && reply[0] == 6
                    && s9se_pic::admit_pic_reply_crc(reply)
                    && s9se_pic::admit_heartbeat_ack(reply)
            }
            Self::Enable(_) => reply == [0x15, 1],
            Self::Voltage(_) => reply == [0x10, 1],
        };
        if valid {
            Ok(())
        } else {
            Err(format!("BM1393 PIC {self:?} reply not acknowledged"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bm1393Reply {
    Complete,
    Bytes(Vec<u8>),
    Eeprom(Box<[u8; 256]>),
    Coverage(Vec<(u8, u16)>),
    Returns(Vec<[u32; 2]>),
    Submitted(Vec<bool>),
    ActiveChains(Vec<u8>),
}

pub trait Bm1393Io {
    fn execute(
        &mut self,
        action: &Bm1393Action,
    ) -> impl Future<Output = Result<Bm1393Reply, String>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1393Failure {
    pub detail: String,
    pub shutdown_errors: Vec<String>,
}
impl std::fmt::Display for Bm1393Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; shutdown errors: {:?}",
            self.detail, self.shutdown_errors
        )
    }
}
impl std::error::Error for Bm1393Failure {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1393State {
    Prepared,
    Starting,
    Running,
    Terminal,
}

pub struct Bm1393Runtime<T: Bm1393Io> {
    io: T,
    chains: Vec<u8>,
    active_chains: Vec<u8>,
    frequency_mhz: u16,
    voltage_mv: u16,
    state: Bm1393State,
    custody_started: bool,
    coverage: BTreeMap<u8, ChainCoverageCertificate>,
}

impl<T: Bm1393Io> Bm1393Runtime<T> {
    /// Physical plug mapping is observed by the adapter, not inferred here.
    pub fn new(
        io: T,
        chains: Vec<u8>,
        frequency_mhz: u16,
        voltage_mv: u16,
    ) -> Result<Self, String> {
        if chains.is_empty()
            || chains.len() > 3
            || chains.iter().any(|c| *c > 15)
            || chains.windows(2).any(|w| w[0] >= w[1])
        {
            return Err("BM1393 needs 1..3 unique ordered physical chains".into());
        }
        if !(100..=400).contains(&frequency_mhz)
            || !FREQ_HIGH_PLL_1393.iter().any(|r| r.0 == frequency_mhz)
            || !(8500..=9500).contains(&voltage_mv)
        {
            return Err("BM1393 beta operating point outside exact stock table".into());
        }
        Ok(Self {
            io,
            active_chains: chains.clone(),
            chains,
            frequency_mhz,
            voltage_mv,
            state: Bm1393State::Prepared,
            custody_started: false,
            coverage: BTreeMap::new(),
        })
    }
    pub fn state(&self) -> Bm1393State {
        self.state
    }
    pub fn active_chains(&self) -> &[u8] {
        &self.active_chains
    }
    async fn refresh_active_chains(&mut self) -> Result<(), String> {
        let Bm1393Reply::ActiveChains(chains) =
            self.io.execute(&Bm1393Action::ReadActiveChains).await?
        else {
            return Err("BM1393 active population reply missing".into());
        };
        if chains.is_empty()
            || chains.windows(2).any(|pair| pair[0] >= pair[1])
            || chains
                .iter()
                .any(|chain| !self.active_chains.contains(chain))
        {
            return Err("BM1393 active population empty, foreign, or resurrected".into());
        }
        self.active_chains = chains;
        Ok(())
    }
    pub fn io(&self) -> &T {
        &self.io
    }
    pub fn io_mut(&mut self) -> &mut T {
        &mut self.io
    }
    async fn done(&mut self, action: Bm1393Action) -> Result<(), String> {
        match self.io.execute(&action).await? {
            Bm1393Reply::Complete => Ok(()),
            _ => Err(format!("unexpected BM1393 reply for {action:?}")),
        }
    }
    async fn pic(&mut self, chain: u8, command: Bm1393PicCommand) -> Result<(), String> {
        match self
            .io
            .execute(&Bm1393Action::Pic { chain, command })
            .await?
        {
            Bm1393Reply::Bytes(reply) => command.validate(&reply),
            _ => Err("PIC did not return bytes".into()),
        }
    }
    async fn asic(&mut self, chain: u8, bytes: &[u8]) -> Result<(), String> {
        self.done(Bm1393Action::Asic {
            chain,
            bytes: bytes.to_vec(),
        })
        .await
    }
    pub async fn start(&mut self) -> Result<(), Bm1393Failure> {
        if self.state != Bm1393State::Prepared {
            return Err(Bm1393Failure {
                detail: "BM1393 owner cannot restart".into(),
                shutdown_errors: Vec::new(),
            });
        }
        self.state = Bm1393State::Starting;
        if let Err(detail) = self.start_inner().await {
            let shutdown_errors = self.closeout().await;
            return Err(Bm1393Failure {
                detail,
                shutdown_errors,
            });
        }
        self.state = Bm1393State::Running;
        Ok(())
    }
    /// A board-local phase may fail only into the retained adapter's checked
    /// cut. Shared transport errors already fence that adapter globally, so
    /// they cannot produce this local success or continue another board.
    async fn retain_chain_result<V>(
        &mut self,
        chain: u8,
        result: Result<V, String>,
    ) -> Result<Option<V>, String> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(detail) => {
                self.done(Bm1393Action::IsolateChain { chain })
                    .await
                    .map_err(|cut| format!("chain{chain}: {detail}; isolation unproven: {cut}"))?;
                self.refresh_active_chains()
                    .await
                    .map_err(|remaining| format!("chain{chain}: {detail}; {remaining}"))?;
                if self.active_chains.contains(&chain) {
                    return Err(format!(
                        "chain{chain}: {detail}; isolation did not retire chain"
                    ));
                }
                self.coverage.remove(&chain);
                Ok(None)
            }
        }
    }
    async fn startup_profile(&mut self, chain: u8) -> Result<Bm1393FactoryProfile, String> {
        self.done(Bm1393Action::ChainReset {
            chain,
            asserted: true,
        })
        .await?;
        self.pic(chain, Bm1393PicCommand::Enable(false)).await?;
        let bytes = match self
            .io
            .execute(&Bm1393Action::ReadProtectedEeprom { chain })
            .await?
        {
            Bm1393Reply::Eeprom(bytes) => bytes,
            _ => return Err("protected EEPROM read returned no image".into()),
        };
        let profile = Bm1393FactoryProfile::decode(&bytes)?;
        profile.rail_code(self.voltage_mv)?;
        self.pic(chain, Bm1393PicCommand::Version).await?;
        Ok(profile)
    }
    async fn enumerate_chain(&mut self, chain: u8) -> Result<ChainCoverageCertificate, String> {
        for _ in 0..3 {
            self.asic(chain, &pack_chain_inactive_vil()).await?;
            self.done(Bm1393Action::DelayMs(30)).await?;
        }
        for slot in 0..S9SE_ASSIGNMENT_SLOTS {
            let address = slot * S9SE_ADDR_INTERVAL;
            self.asic(chain, &pack_set_address_vil(address)).await?;
            self.done(Bm1393Action::DelayMs(2)).await?;
            self.asic(chain, &s9se_regs::pack_core_number(address))
                .await?;
            self.done(Bm1393Action::DelayMs(50)).await?;
        }
        let observed = match self
            .io
            .execute(&Bm1393Action::ReadChipCoverage { chain })
            .await?
        {
            Bm1393Reply::Coverage(replies) if replies.iter().all(|r| r.1 == 0x1393) => {
                replies.into_iter().map(|r| r.0).collect::<Vec<_>>()
            }
            _ => return Err("BM1393 register-zero coverage identity mismatch".into()),
        };
        let expected = (0..S9SE_CHIPS_PER_CHAIN).map(|i| i * 4).collect::<Vec<_>>();
        ChainCoverageCertificate::certify(&expected, &observed).map_err(|e| e.to_string())
    }
    async fn start_inner(&mut self) -> Result<(), String> {
        // The complete observed population remains owned for final closeout.
        self.custody_started = true;
        self.done(Bm1393Action::StartCustody {
            chains: self.chains.clone(),
        })
        .await?;
        let mut profiles = BTreeMap::new();
        for chain in self.active_chains.clone() {
            let result = self.startup_profile(chain).await;
            if let Some(profile) = self.retain_chain_result(chain, result).await? {
                profiles.insert(chain, profile);
            }
        }
        for _ in 0..5 {
            for chain in self.active_chains.clone() {
                let result = self.pic(chain, Bm1393PicCommand::Heartbeat).await;
                self.retain_chain_result(chain, result).await?;
            }
            self.done(Bm1393Action::CheckHealth).await?;
            self.done(Bm1393Action::DelayMs(1000)).await?;
        }
        for chain in self.active_chains.clone() {
            self.done(Bm1393Action::MaintainPicHeartbeat { chain })
                .await?;
        }
        self.done(Bm1393Action::ConfigureFabric).await?;
        for chain in self.active_chains.clone() {
            let result = async {
                self.pic(
                    chain,
                    Bm1393PicCommand::Voltage(profiles[&chain].rail_code(self.voltage_mv)?),
                )
                .await?;
                self.pic(chain, Bm1393PicCommand::Enable(true)).await
            }
            .await;
            self.retain_chain_result(chain, result).await?;
        }
        self.done(Bm1393Action::DelayMs(1000)).await?;
        for chain in self.active_chains.clone() {
            let result = self
                .done(Bm1393Action::ChainReset {
                    chain,
                    asserted: false,
                })
                .await;
            self.retain_chain_result(chain, result).await?;
        }
        self.done(Bm1393Action::DelayMs(1000)).await?;
        for chain in self.active_chains.clone() {
            let result = self.enumerate_chain(chain).await;
            if let Some(coverage) = self.retain_chain_result(chain, result).await? {
                self.coverage.insert(chain, coverage);
            }
        }
        let &(_, divider, pll_mhz) = FREQ_HIGH_PLL_1393
            .iter()
            .find(|r| r.0 == self.frequency_mhz)
            .ok_or("missing BM1393 frequency row")?;
        let &(_, pll_word) = FREQ_PLL_1393
            .iter()
            .find(|r| r.0 == pll_mhz)
            .ok_or("missing BM1393 PLL word")?;
        for chain in self.active_chains.clone() {
            let result = async {
                for frame in pack_unused_pll_park_frames().into_iter().chain(
                    pack_operational_pll_frames(pll_word, divider)
                        .map_err(|_| "invalid BM1393 divider")?,
                ) {
                    self.asic(chain, &frame).await?;
                    self.done(Bm1393Action::DelayMs(10)).await?;
                }
                Ok(())
            }
            .await;
            self.retain_chain_result(chain, result).await?;
        }
        // Stock pre-open enables13 positions across all4 banks for sensors.
        self.open_cores(13).await?;
        for chain in self.active_chains.clone() {
            let result = self
                .asic(
                    chain,
                    &s9se_regs::pack_baud_one_chain(1).map_err(|_| "bad working baud")?,
                )
                .await;
            self.retain_chain_result(chain, result).await?;
        }
        self.done(Bm1393Action::DelayMs(10)).await?;
        self.done(Bm1393Action::SetBaud { divisor: 1 }).await?;
        // Broadcast baud replaces MISC I2C bits: configure sensors afterward.
        for chain in self.active_chains.clone() {
            let result = self
                .done(Bm1393Action::ConfigureTemperature {
                    chain,
                    profile: profiles[&chain].clone(),
                })
                .await;
            self.retain_chain_result(chain, result).await?;
        }
        for chain in self.active_chains.clone() {
            let result = async {
                self.asic(chain, &s9se_regs::pack_ticket_mask_broadcast(0x3f))
                    .await?;
                self.asic(chain, &s9se_regs::pack_clock_delay_control(true))
                    .await
            }
            .await;
            self.retain_chain_result(chain, result).await?;
        }
        self.done(Bm1393Action::CheckHealth).await?;
        self.open_cores(52).await?;
        let timeout = stock_timeout_s9se(u32::from(self.frequency_mhz))
            .map_err(|_| "invalid BM1393 work timeout")?;
        self.done(Bm1393Action::SetWorkTimeout {
            word: timeout_control_word(timeout, 1),
        })
        .await?;
        self.done(Bm1393Action::CheckHealth).await?;
        self.refresh_active_chains().await
    }
    async fn open_cores(&mut self, positions: u8) -> Result<(), String> {
        for position in 0..positions {
            for chain in self.active_chains.clone() {
                let result = async {
                    for bank in 0..4 {
                        self.asic(
                            chain,
                            &s9se_regs::pack_enable_core_clock(bank * 52 + position),
                        )
                        .await?;
                    }
                    self.done(Bm1393Action::DelayMs(5)).await?;
                    let mut words = [0; 13];
                    words[0] = open_core_tw0(chain);
                    self.done(Bm1393Action::Work { chain, words }).await?;
                    self.done(Bm1393Action::DelayMs(10)).await
                }
                .await;
                self.retain_chain_result(chain, result).await?;
            }
        }
        Ok(())
    }
    pub async fn submit_work(
        &mut self,
        chain: u8,
        work_id: u16,
        data: &[u8; 12],
        midstate: &[u8; 32],
    ) -> Result<(), Bm1393Failure> {
        if self.state != Bm1393State::Running
            || self
                .active_chains
                .iter()
                .any(|chain| !self.coverage.contains_key(chain))
            || !self.active_chains.contains(&chain)
        {
            return Err(Bm1393Failure {
                detail: "BM1393 work requires running exact covered chain".into(),
                shutdown_errors: Vec::new(),
            });
        }
        let result = async {
            let words = encode_bm1393_work(chain, work_id, data, midstate)?;
            self.done(Bm1393Action::CheckHealth).await?;
            self.done(Bm1393Action::Work { chain, words }).await
        }
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(detail) => Err(Bm1393Failure {
                detail,
                shutdown_errors: self.closeout().await,
            }),
        }
    }
    /// A bounded batch has one health check and one retained FIFO operation.
    /// Backpressure is reported per chain; partial frame faults remain fatal.
    pub async fn submit_batch(
        &mut self,
        items: Vec<(u8, [u32; 13])>,
    ) -> Result<Vec<bool>, Bm1393Failure> {
        let result = async {
            if self.state != Bm1393State::Running
                || self
                    .active_chains
                    .iter()
                    .any(|chain| !self.coverage.contains_key(chain))
                || items.is_empty()
                || items.len() > BM1393_MAX_WORK_BATCH
                || items.iter().any(|(chain, words)| {
                    !self.active_chains.contains(chain)
                        || words[0] != (0x0180_0000 | (u32::from(*chain) << 16))
                        || words[1] >= BM1393_WORK_ID_SLOTS as u32
                })
            {
                return Err("BM1393 batch requires bounded exact covered work".into());
            }
            self.done(Bm1393Action::CheckHealth).await?;
            self.refresh_active_chains().await?;
            let Bm1393Reply::Submitted(accepted) = self
                .io
                .execute(&Bm1393Action::WorkBatch {
                    items: items.clone(),
                })
                .await?
            else {
                return Err("BM1393 batch returned wrong reply".into());
            };
            if accepted.len() != items.len() {
                return Err("BM1393 batch reply length mismatch".into());
            }
            let mut blocked = [false; 16];
            for ((chain, _), accepted) in items.iter().zip(&accepted) {
                if *accepted && blocked[usize::from(*chain)] {
                    return Err("BM1393 batch reordered work within a chain".into());
                }
                blocked[usize::from(*chain)] |= !accepted;
            }
            Ok(accepted)
        }
        .await;
        match result {
            Ok(accepted) => Ok(accepted),
            Err(detail) => Err(Bm1393Failure {
                detail,
                shutdown_errors: self.closeout().await,
            }),
        }
    }
    pub async fn isolate_chain(&mut self, chain: u8) -> Result<(), Bm1393Failure> {
        let result = async {
            if self.state != Bm1393State::Running || !self.active_chains.contains(&chain) {
                return Err("BM1393 isolation requires an active owned chain".into());
            }
            self.done(Bm1393Action::IsolateChain { chain }).await?;
            self.refresh_active_chains().await?;
            if self.active_chains.contains(&chain) {
                return Err("BM1393 isolation did not remove the fenced chain".into());
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(detail) => Err(Bm1393Failure {
                detail,
                shutdown_errors: self.closeout().await,
            }),
        }
    }
    pub async fn poll_returns(&mut self) -> Result<Vec<S9SeFifoRecord>, Bm1393Failure> {
        if self.state != Bm1393State::Running {
            return Err(Bm1393Failure {
                detail: "BM1393 owner is not running".into(),
                shutdown_errors: Vec::new(),
            });
        }
        let result = async {
            self.done(Bm1393Action::CheckHealth).await?;
            self.refresh_active_chains().await?;
            let Bm1393Reply::Returns(records) = self
                .io
                .execute(&Bm1393Action::ReadReturns { maximum: 128 })
                .await?
            else {
                return Err("BM1393 FIFO returned wrong reply".into());
            };
            if records.len() > 128 {
                return Err("BM1393 FIFO exceeded bounded read".into());
            }
            Ok(records
                .into_iter()
                .filter_map(|r| classify_return_record(r[0], r[1]))
                .filter(|r| match r {
                    S9SeFifoRecord::Nonce { chain, .. } => self.active_chains.contains(chain),
                    S9SeFifoRecord::Register { .. } => false,
                })
                .collect())
        }
        .await;
        match result {
            Ok(records) => Ok(records),
            Err(detail) => Err(Bm1393Failure {
                detail,
                shutdown_errors: self.closeout().await,
            }),
        }
    }
    async fn closeout(&mut self) -> Vec<String> {
        self.state = Bm1393State::Terminal;
        self.active_chains.clear();
        self.coverage.clear();
        let mut errors = Vec::new();
        if !self.custody_started {
            return errors;
        }
        if let Err(e) = self.done(Bm1393Action::StopWork).await {
            errors.push(e);
        }
        for chain in self.chains.clone() {
            if let Err(e) = self
                .done(Bm1393Action::ChainReset {
                    chain,
                    asserted: true,
                })
                .await
            {
                errors.push(e);
            }
            if let Err(e) = self.pic(chain, Bm1393PicCommand::Enable(false)).await {
                errors.push(e);
            }
        }
        if errors.is_empty() {
            if let Err(e) = self.done(Bm1393Action::StopCustody).await {
                errors.push(e);
            }
        }
        errors
    }
    pub async fn shutdown(&mut self) -> Result<(), Bm1393Failure> {
        let shutdown_errors = self.closeout().await;
        if shutdown_errors.is_empty() {
            Ok(())
        } else {
            Err(Bm1393Failure {
                detail: "BM1393 shutdown unproven; watcher retained".into(),
                shutdown_errors,
            })
        }
    }
}

#[cfg(test)]
#[path = "bm1393_native_tests.rs"]
mod tests;
