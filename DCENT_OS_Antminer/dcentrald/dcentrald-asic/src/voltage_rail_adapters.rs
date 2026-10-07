//! Thin VoltageRail adapters over live PIC / dsPIC controllers (P1-2).
//!
//! # Role
//!
//! `dcentrald-common::voltage_rail` owns the pure trait, BoardDesc adapter
//! binding, and per-op admission policy. This module is the **I/O edge**:
//! wrap `DspicController` / `PicController` and map `AsicError` →
//! `VoltageRailError`. Host tests inject `RecordingVoltageRail` via
//! [`dcentrald_common::BackendVoltageRail`] without linking this crate.
//!
//! # Maturity
//!
//! - **EXPERIMENTAL** thin wrappers: behavior-preserving façades over proven
//!   controller methods; not a second voltage protocol.
//! - **NOT IMPLEMENTED**: TAS5782M / ExternalDac wire path — use
//!   [`UnsupportedExternalDacRail`] until a maintainable DAC adapter lands.
//!
//! # Safety
//!
//! Energizing ops call [`admit_voltage_rail_op`] before I/O (defense in depth
//! with the controller's own `ensure_dspic_voltage_command_allowed`). Never
//! return `Ok(())` on a miss.

use dcentrald_common::{
    admit_voltage_rail_op, chip_driver_set_voltage_admission, pic16_mv_to_dac,
    voltage_rail_io_error, AsicProtocolIdentity, UnsupportedExternalDacRail, VoltageRail,
    VoltageRailAdapterKind, VoltageRailError, VoltageRailOp,
};
use dcentrald_hal::stock_fpga_iic::StockFpgaI2c;

use crate::dspic::{DspicController, DspicFirmware, Pic0x89Service};
use crate::pic::PicController;
use crate::pic1704::Pic1704Service;
use crate::AsicError;

/// Map ASIC/PIC I/O failures into the pure VoltageRail error surface.
pub fn map_asic_error(err: AsicError) -> VoltageRailError {
    match err {
        AsicError::Pic { addr, detail } => {
            voltage_rail_io_error(format!("PIC 0x{addr:02X}: {detail}"))
        }
        AsicError::Hal(e) => voltage_rail_io_error(format!("HAL: {e}")),
        other => voltage_rail_io_error(other.to_string()),
    }
}

fn firmware_byte(fw: DspicFirmware) -> Option<u8> {
    match fw {
        DspicFirmware::Fw82 => Some(0x82),
        DspicFirmware::Fw86 => Some(0x86),
        DspicFirmware::Fw89 => Some(0x89),
        DspicFirmware::Fw8A => Some(0x8A),
        DspicFirmware::FwB9 => Some(0xB9),
        DspicFirmware::FwFE => Some(0xFE),
        DspicFirmware::Other(b) => Some(b),
        DspicFirmware::Unknown => None,
    }
}

/// VoltageRail over a mutable dsPIC33EP hashboard controller (AM2 class).
pub struct DsPicVoltageRail<'a, 'ctrl> {
    pub ctrl: &'a mut DspicController<'ctrl>,
    /// Legacy flag; common admission refuses fw=0x86 regardless of its value.
    pub trust_degraded: bool,
}

impl<'a, 'ctrl> DsPicVoltageRail<'a, 'ctrl> {
    pub fn new(ctrl: &'a mut DspicController<'ctrl>, trust_degraded: bool) -> Self {
        Self {
            ctrl,
            trust_degraded,
        }
    }

    fn fw_byte(&self) -> Option<u8> {
        firmware_byte(self.ctrl.firmware())
    }

    fn admit(&self, op: VoltageRailOp) -> Result<(), VoltageRailError> {
        admit_voltage_rail_op(
            VoltageRailAdapterKind::DsPic33Ep,
            self.fw_byte(),
            self.trust_degraded,
            op,
        )
    }
}

impl VoltageRail for DsPicVoltageRail<'_, '_> {
    fn set_mv(&mut self, mv: u16) -> Result<(), VoltageRailError> {
        self.admit(VoltageRailOp::SetMv)?;
        self.ctrl.set_voltage(mv).map_err(map_asic_error)
    }

    fn enable(&mut self) -> Result<(), VoltageRailError> {
        self.admit(VoltageRailOp::Enable)?;
        self.ctrl.enable_voltage().map_err(map_asic_error)
    }

    fn disable(&mut self) -> Result<(), VoltageRailError> {
        self.admit(VoltageRailOp::Disable)?;
        self.ctrl.disable_voltage().map_err(map_asic_error)
    }

    fn heartbeat(&mut self) -> Result<(), VoltageRailError> {
        self.admit(VoltageRailOp::Heartbeat)?;
        self.ctrl.send_heartbeat().map_err(map_asic_error)
    }

    fn measure_mv(&mut self) -> Result<Option<u16>, VoltageRailError> {
        self.admit(VoltageRailOp::Measure)?;
        match self.ctrl.measure_voltage() {
            Ok(mv) => Ok(Some(mv)),
            Err(e) => Err(map_asic_error(e)),
        }
    }

    fn firmware_identity(&self) -> Option<u8> {
        self.fw_byte()
    }
}

/// VoltageRail over PIC16F1704 (S9 ChipDriver path).
///
/// `set_mv` takes **millivolts** and encodes via pure
/// [`pic16_mv_to_dac`] — callers no longer pass raw PIC DAC on this facet.
pub struct Pic16VoltageRail<'a, 'ctrl> {
    pub ctrl: &'a mut PicController<'ctrl>,
}

impl<'a, 'ctrl> Pic16VoltageRail<'a, 'ctrl> {
    pub fn new(ctrl: &'a mut PicController<'ctrl>) -> Self {
        Self { ctrl }
    }

    fn admit(op: VoltageRailOp) -> Result<(), VoltageRailError> {
        admit_voltage_rail_op(VoltageRailAdapterKind::Pic16ChipDriver, None, false, op)
    }
}

impl VoltageRail for Pic16VoltageRail<'_, '_> {
    fn set_mv(&mut self, mv: u16) -> Result<(), VoltageRailError> {
        Self::admit(VoltageRailOp::SetMv)?;
        let dac = pic16_mv_to_dac(mv);
        self.ctrl.set_voltage(dac).map_err(map_asic_error)
    }

    fn enable(&mut self) -> Result<(), VoltageRailError> {
        Self::admit(VoltageRailOp::Enable)?;
        self.ctrl.enable_voltage().map_err(map_asic_error)
    }

    fn disable(&mut self) -> Result<(), VoltageRailError> {
        Self::admit(VoltageRailOp::Disable)?;
        self.ctrl.disable_voltage().map_err(map_asic_error)
    }

    fn heartbeat(&mut self) -> Result<(), VoltageRailError> {
        Self::admit(VoltageRailOp::Heartbeat)?;
        self.ctrl.send_heartbeat().map_err(map_asic_error)
    }

    fn measure_mv(&mut self) -> Result<Option<u16>, VoltageRailError> {
        Self::admit(VoltageRailOp::Measure)?;
        // PIC read_voltage returns DAC byte; convert to mV for the facet.
        match self.ctrl.read_voltage() {
            Ok(dac) => Ok(Some(dcentrald_common::pic16_dac_to_mv(dac))),
            Err(e) => Err(map_asic_error(e)),
        }
    }
}

/// VoltageRail over AM2 hybrid's production controller type ([`Pic0x89Service`]).
///
/// This is the adapter engines construct on s19j-hybrid paths ( multi-PIC
/// enable, open-core demotion, clean-stop). Same policy gate as
/// [`DsPicVoltageRail`]; I/O delegates to the framed/bare Pic0x89 service.
pub struct Pic0x89VoltageRail<'a> {
    pub svc: &'a mut Pic0x89Service,
    pub trust_degraded: bool,
}

impl<'a> Pic0x89VoltageRail<'a> {
    pub fn new(svc: &'a mut Pic0x89Service, trust_degraded: bool) -> Self {
        Self {
            svc,
            trust_degraded,
        }
    }

    fn fw_byte(&self) -> Option<u8> {
        firmware_byte(self.svc.firmware())
    }

    fn admit(&self, op: VoltageRailOp) -> Result<(), VoltageRailError> {
        admit_voltage_rail_op(
            VoltageRailAdapterKind::DsPic33Ep,
            self.fw_byte(),
            self.trust_degraded,
            op,
        )
    }
}

impl VoltageRail for Pic0x89VoltageRail<'_> {
    fn set_mv(&mut self, mv: u16) -> Result<(), VoltageRailError> {
        self.admit(VoltageRailOp::SetMv)?;
        self.svc.set_voltage(mv).map_err(map_asic_error)
    }

    fn enable(&mut self) -> Result<(), VoltageRailError> {
        self.admit(VoltageRailOp::Enable)?;
        self.svc.enable_voltage().map_err(map_asic_error)
    }

    fn disable(&mut self) -> Result<(), VoltageRailError> {
        self.admit(VoltageRailOp::Disable)?;
        self.svc.disable_voltage().map_err(map_asic_error)
    }

    fn heartbeat(&mut self) -> Result<(), VoltageRailError> {
        self.admit(VoltageRailOp::Heartbeat)?;
        self.svc.send_heartbeat().map_err(map_asic_error)
    }

    fn measure_mv(&mut self) -> Result<Option<u16>, VoltageRailError> {
        self.admit(VoltageRailOp::Measure)?;
        match self.svc.measure_voltage() {
            Ok(mv) => Ok(Some(mv)),
            Err(e) => Err(map_asic_error(e)),
        }
    }

    fn firmware_identity(&self) -> Option<u8> {
        self.fw_byte()
    }
}

/// VoltageRail over stock Bitmain FPGA PIC I2C (S9 `--stock-fpga` path).
///
/// `set_mv` encodes via pure [`pic16_mv_to_dac`]; chain is fixed for the rail
/// instance (stock FPGA addresses PIC per physical chain 5–8).
pub struct StockFpgaVoltageRail<'a> {
    pub i2c: &'a StockFpgaI2c<'a>,
    pub chain: u8,
}

impl<'a> StockFpgaVoltageRail<'a> {
    pub fn new(i2c: &'a StockFpgaI2c<'a>, chain: u8) -> Self {
        Self { i2c, chain }
    }

    fn admit(op: VoltageRailOp) -> Result<(), VoltageRailError> {
        admit_voltage_rail_op(VoltageRailAdapterKind::Pic16ChipDriver, None, false, op)
    }

    fn map_hal(err: dcentrald_hal::HalError, chain: u8) -> VoltageRailError {
        voltage_rail_io_error(format!("stock FPGA PIC chain {chain}: {err}"))
    }
}

impl VoltageRail for StockFpgaVoltageRail<'_> {
    fn set_mv(&mut self, mv: u16) -> Result<(), VoltageRailError> {
        Self::admit(VoltageRailOp::SetMv)?;
        let dac = pic16_mv_to_dac(mv);
        self.i2c
            .set_voltage(self.chain, dac)
            .map_err(|e| Self::map_hal(e, self.chain))
    }

    fn enable(&mut self) -> Result<(), VoltageRailError> {
        Self::admit(VoltageRailOp::Enable)?;
        self.i2c
            .enable_voltage(self.chain, true)
            .map_err(|e| Self::map_hal(e, self.chain))
    }

    fn disable(&mut self) -> Result<(), VoltageRailError> {
        Self::admit(VoltageRailOp::Disable)?;
        self.i2c
            .enable_voltage(self.chain, false)
            .map_err(|e| Self::map_hal(e, self.chain))
    }

    fn heartbeat(&mut self) -> Result<(), VoltageRailError> {
        Self::admit(VoltageRailOp::Heartbeat)?;
        self.i2c
            .send_heartbeat(self.chain)
            .map_err(|e| Self::map_hal(e, self.chain))
    }
}

/// VoltageRail over PIC1704 short-form register controller (CV1835 / BB class).
///
/// PIC1704 does **not** expose a millivolt set-point on the short-form protocol
/// held offline — only DC-DC enable/disable + heartbeat + measure. `set_mv`
/// therefore returns honest [`VoltageRailError::Unsupported`] (do not map to
/// Ok). Enable/disable/heartbeat/measure are live.
pub struct Pic1704VoltageRail<'a> {
    pub svc: &'a mut Pic1704Service,
}

impl<'a> Pic1704VoltageRail<'a> {
    pub fn new(svc: &'a mut Pic1704Service) -> Self {
        Self { svc }
    }

    fn admit(op: VoltageRailOp) -> Result<(), VoltageRailError> {
        admit_voltage_rail_op(VoltageRailAdapterKind::Pic1704, None, false, op)
    }
}

impl VoltageRail for Pic1704VoltageRail<'_> {
    fn set_mv(&mut self, mv: u16) -> Result<(), VoltageRailError> {
        Self::admit(VoltageRailOp::SetMv)?;
        // Evidence-exhausted: SOURCE_HAL short-form map has no writable mV/DAC
        // register (REG_VOLTAGE_* are read-only feedback). Pure SSOT:
        // crate::pic1704::protocol::admit_short_form_set_mv.
        crate::pic1704::protocol::admit_short_form_set_mv(mv)
    }

    fn enable(&mut self) -> Result<(), VoltageRailError> {
        Self::admit(VoltageRailOp::Enable)?;
        self.svc.enable_dc_dc(true).map_err(map_asic_error)
    }

    fn disable(&mut self) -> Result<(), VoltageRailError> {
        Self::admit(VoltageRailOp::Disable)?;
        self.svc.enable_dc_dc(false).map_err(map_asic_error)
    }

    fn heartbeat(&mut self) -> Result<(), VoltageRailError> {
        Self::admit(VoltageRailOp::Heartbeat)?;
        self.svc.heartbeat().map_err(map_asic_error)
    }

    fn measure_mv(&mut self) -> Result<Option<u16>, VoltageRailError> {
        Self::admit(VoltageRailOp::Measure)?;
        match self.svc.read_voltage_mv() {
            Ok(mv) => Ok(Some(mv)),
            Err(e) => Err(map_asic_error(e)),
        }
    }
}

/// ChipDriver::set_voltage strangler (P1-2): admit ownership then Pic16 VoltageRail.
///
/// - BM1387 / BM1366 industrial PIC path: admitted → [`Pic16VoltageRail::set_mv`]
/// - BM1362 / BM1368 / BM1370 / BM139x: refused by pure ownership SSOT (route
///   VoltageRail / dsPIC / external DAC — never silent Ok)
pub fn chip_driver_set_voltage_via_pic16_rail(
    identity: AsicProtocolIdentity,
    pic: &mut PicController,
    voltage_mv: u16,
) -> Result<(), VoltageRailError> {
    chip_driver_set_voltage_admission(identity)?;
    let mut rail = Pic16VoltageRail::new(pic);
    rail.set_mv(voltage_mv)
}

/// Map VoltageRailError into AsicError for ChipDriver trait surface.
pub fn voltage_rail_error_as_asic(err: VoltageRailError, pic_addr: u8) -> AsicError {
    match err {
        VoltageRailError::Io { detail } => AsicError::Pic {
            addr: pic_addr,
            detail,
        },
        other => AsicError::InvalidParameter(other.to_string()),
    }
}

/// Factory: BoardDesc adapter kind → trait object when no live controller.
///
/// ExternalDac / RuntimeDiscovered stay fail-closed. Live Pic16/DsPic rails
/// require a controller reference — use [`Pic16VoltageRail`] /
/// [`DsPicVoltageRail`] / [`Pic0x89VoltageRail`] / [`StockFpgaVoltageRail`].
pub fn external_dac_rail() -> UnsupportedExternalDacRail {
    UnsupportedExternalDacRail
}

/// Passive bench rail over a supplied measurement. This adapter owns no bus,
/// GPIO or controller handle. It cannot scan, enable, keep alive or cut power.
/// In particular, `disable` must not claim that a physical SafeOff occurred.
pub struct S21DiscoverOnlyRail {
    discovery: dcentrald_common::voltage_rail::S21PsuDiscovery,
    observed_mv: Option<u16>,
}

impl S21DiscoverOnlyRail {
    pub fn new(
        target: &str,
        boards: &[(&str, u16)],
        psu: Option<dcentrald_common::voltage_rail::BenchPsuIdentity<'_>>,
        observed_mv: Option<u16>,
    ) -> Result<Self, VoltageRailError> {
        Ok(Self {
            discovery: dcentrald_common::voltage_rail::discover_s21_psu(target, boards, psu)?,
            observed_mv,
        })
    }

    pub fn discovery(&self) -> &dcentrald_common::voltage_rail::S21PsuDiscovery {
        &self.discovery
    }

    fn no_control() -> Result<(), VoltageRailError> {
        Err(VoltageRailError::Unsupported {
            detail:
                "discover-only has no hardware control; use the retained hardware owner for SafeOff"
                    .into(),
        })
    }
}

impl VoltageRail for S21DiscoverOnlyRail {
    fn set_mv(&mut self, _mv: u16) -> Result<(), VoltageRailError> {
        Self::no_control()
    }
    fn enable(&mut self) -> Result<(), VoltageRailError> {
        Self::no_control()
    }
    fn disable(&mut self) -> Result<(), VoltageRailError> {
        Self::no_control()
    }
    fn heartbeat(&mut self) -> Result<(), VoltageRailError> {
        Self::no_control()
    }
    /// Caller-supplied observation, not a fresh hardware measurement.
    fn measure_mv(&mut self) -> Result<Option<u16>, VoltageRailError> {
        Ok(self.observed_mv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcentrald_common::{resolve_voltage_rail_adapter, BoardDesc, VoltageRailAdapterKind};

    #[test]
    fn t21_positive_path_sim() {
        use dcentrald_common::voltage_rail::BenchPsuIdentity;
        assert_eq!(
            dcentrald_common::voltage_rail::T21_APW11A_VERSION_KEYS,
            dcentrald_silicon_profiles::t21_stock_topol::T21_PSU_VERSION_KEYS
        );
        let boards = [("BHB68701", 108), ("BHB68703", 108), ("BHB68705", 108)];
        let mut rail = S21DiscoverOnlyRail::new(
            "am3-t21",
            &boards,
            Some(BenchPsuIdentity {
                family: "APW11A",
                address_7bit: 0x10,
                version: 66,
            }),
            Some(0),
        )
        .unwrap();
        assert_eq!(
            rail.discovery().profile.asic(),
            AsicProtocolIdentity::Bm1368
        );
        assert_eq!(rail.discovery().profile.chips_per_chain(), 108);
        assert_eq!(rail.measure_mv().unwrap(), Some(0));
        assert_eq!(
            rail.firmware_identity(),
            None,
            "PSU version is not PIC firmware identity"
        );
        assert!(rail.discovery().polarity_card.contains("undriven"));
    }

    #[test]
    fn s21plus_positive_path_sim() {
        let boards = [("A3HB70701", 55), ("A3HB70702", 55), ("A3HB70703", 55)];
        let mut rail = S21DiscoverOnlyRail::new("amlogic-s21plus", &boards, None, None).unwrap();
        assert_eq!(
            rail.discovery().profile.asic(),
            AsicProtocolIdentity::Bm1370
        );
        assert_eq!(rail.discovery().profile.chips_per_chain(), 55);
        assert_eq!(rail.measure_mv().unwrap(), None);
        assert!(rail.discovery().polarity_card.contains("undriven"));
    }

    #[test]
    fn discover_only_refuses_all_control_including_false_safeoff() {
        for (target, name, count) in [
            ("am3-t21", "BHB68701", 108),
            ("amlogic-s21plus", "A3HB70701", 55),
        ] {
            let mut rail =
                S21DiscoverOnlyRail::new(target, &[(name, count); 3], None, Some(1234)).unwrap();
            for result in [
                rail.set_mv(12000),
                rail.enable(),
                rail.disable(),
                rail.heartbeat(),
            ] {
                assert!(matches!(result, Err(VoltageRailError::Unsupported { .. })));
            }
            assert_eq!(rail.measure_mv().unwrap(), Some(1234));
            assert!(rail.firmware_identity().is_none());
        }
    }

    #[test]
    fn external_dac_factory_is_unsupported_on_energize() {
        let mut rail = external_dac_rail();
        assert!(rail.set_mv(12_000).is_err());
        assert!(rail.disable().is_ok());
    }

    #[test]
    fn beta_boards_map_to_adapter_kinds_this_module_covers() {
        let s9 = BoardDesc::am1_s9();
        assert_eq!(
            resolve_voltage_rail_adapter(s9.voltage_controller, s9.asic_protocol),
            VoltageRailAdapterKind::Pic16ChipDriver
        );
        let am2 = BoardDesc::lookup("am2-s19j").expect("registry");
        assert_eq!(
            resolve_voltage_rail_adapter(am2.voltage_controller, am2.asic_protocol),
            VoltageRailAdapterKind::DsPic33Ep
        );
    }

    #[test]
    fn firmware_byte_map_covers_proven_set() {
        assert_eq!(firmware_byte(DspicFirmware::Fw86), Some(0x86));
        assert_eq!(firmware_byte(DspicFirmware::Fw89), Some(0x89));
        assert_eq!(firmware_byte(DspicFirmware::Unknown), None);
        assert_eq!(firmware_byte(DspicFirmware::Other(0x11)), Some(0x11));
    }
}
