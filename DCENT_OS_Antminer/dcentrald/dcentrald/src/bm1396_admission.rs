//! Declaration admission for exact T17e cold300 and S17e factory native routes.
//! Native mapping independently checks this boot's exact fabric, DMA reserve,
//! GPIO identity and actual complete population before any work publication.
use crate::{config::DcentraldConfig, daemon_lifecycle::PlatformIdentitySnapshot};
use dcentrald_common::{AsicProtocolAdmission, GenericConstruction, LifecycleLane, RuntimeStatus};
use dcentrald_common::{AsicProtocolIdentity, BoardFamily, ChainTransportKind, WorkEngineKind};
use dcentrald_hal::platform::stock_bm1396::Model;

#[derive(Debug)]
#[must_use = "consume exact BM1396 model admission in its native runtime"]
pub(crate) struct Bm1396DispatchAdmission {
    model: Model,
    cutoff_c: i16,
    frequency_limit_mhz: u16,
    _protocol: AsicProtocolAdmission,
}
impl Bm1396DispatchAdmission {
    pub(crate) fn model(&self) -> Model {
        self.model
    }
    pub(crate) fn board_target(&self) -> &'static str {
        match self.model {
            Model::T17e => "am2-t17e",
            Model::S17e => "am2-s17e",
        }
    }
    pub(crate) fn cutoff_c(&self) -> i16 {
        self.cutoff_c
    }
    pub(crate) fn frequency_limit_mhz(&self) -> u16 {
        self.frequency_limit_mhz
    }
}

pub(crate) fn admit(
    identity: &PlatformIdentitySnapshot,
    config: &DcentraldConfig,
    protocol: AsicProtocolAdmission,
) -> Result<Bm1396DispatchAdmission, String> {
    if protocol.identity() != AsicProtocolIdentity::Bm1396 {
        return Err("BM1396 native admission requires its consumed protocol authority".into());
    }
    let model = match identity.board_target() {
        "am2-t17e" => Model::T17e,
        "am2-s17e" => Model::S17e,
        _ => {
            return Err(
                "BM1396 native admission requires an exact registered S17e or T17e target".into(),
            )
        }
    };
    let desc = identity
        .board_desc
        .ok_or("BM1396 native BoardDesc missing")?;
    if desc.board_target != identity.board_target()
        || desc.family != BoardFamily::Zynq
        || desc.chain_transport != ChainTransportKind::StockFpga
        || desc.work_engine != WorkEngineKind::FpgaWorkFifo
        || desc.asic_protocol != AsicProtocolIdentity::Bm1396
        || !matches!(
            desc.runtime_status,
            RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::Bm1396Native,
                generic_construction: GenericConstruction::Refused,
            }
        )
        || identity.platform_marker() != "zynq-bm1396-stock"
    {
        return Err("BM1396 native composition or platform declaration disagrees".into());
    }
    Ok(Bm1396DispatchAdmission {
        model,
        cutoff_c: admitted_model_cutoff_c(config, model)?,
        frequency_limit_mhz: config.mining.frequency_mhz,
        _protocol: protocol,
    })
}

// Source-profile validation remains separate from the exact registry/lifecycle
// declaration. Neither declaration replaces the actual native boot admission.
#[cfg(test)]
fn admitted_cutoff_c(config: &DcentraldConfig) -> Result<i16, String> {
    admitted_model_cutoff_c(config, Model::T17e)
}

fn admitted_model_cutoff_c(config: &DcentraldConfig, model: Model) -> Result<i16, String> {
    if config.mining.model.as_deref()
        != Some(match model {
            Model::T17e => "t17e",
            Model::S17e => "s17e",
        })
        || crate::configured_asic_protocol_identity(config)? != Some(AsicProtocolIdentity::Bm1396)
        || config.mining.serial_chip_count != Some(model.expected_chips_per_present_chain() as u8)
        || !config.mining_start_enabled()
        || config.mining.passthrough
        || !config.watchdog.enabled
    {
        return Err(
            "BM1396 requires its exact model/population, enabled native mining and independent watchdog".into(),
        );
    }
    // This first complete source profile uses exact cold-300. The subsequent
    // voltage targets come from admitted per-board factory calibration and
    // fresh thermal populations, never an arbitrary caller voltage override.
    // S17e uses frequency_mhz as an explicit ceiling for the actual factory
    // population; it never rewrites a factory target to fit this ceiling.
    let frequency_admitted = match model {
        Model::T17e => config.mining.frequency_mhz == 300,
        Model::S17e => (55..=530).contains(&config.mining.frequency_mhz),
    };
    if !frequency_admitted
        || config.mining.voltage_mv != 20_000
        || config.mining.version_rolling
        || config.thermal.fan_min_pwm != 30
        || config.thermal.fan_max_pwm != 30
        || config.autotuner.enabled
        || config.hash_on_disconnect.enabled
        || config.donation.enabled
        || config.pool.protocol.as_deref() != Some("sv1")
        || !(16..=80).contains(&config.thermal.dangerous_temp_c)
    {
        return Err("BM1396 requires its source frequency profile/20000mV, quiet30, single-version V1 work, cutoff16..80C and disabled autotuning, disconnect hashing and donation".into());
    }
    Ok(i16::from(config.thermal.dangerous_temp_c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s17e_factory_ceiling_defaults_and_sibling_geometry_are_distinct() {
        let mut config: DcentraldConfig = toml::from_str(include_str!(
            "../../configs/beta/am2-s17e-baked-default.toml"
        ))
        .unwrap();
        assert!(!config.mining.enabled);
        config.mining.enabled = true;
        config.pool.url = "stratum+tcp://127.0.0.1:3333".into();
        config.pool.worker = "offline.source.profile".into();
        assert_eq!(admitted_model_cutoff_c(&config, Model::S17e).unwrap(), 75);
        assert!(admitted_model_cutoff_c(&config, Model::T17e).is_err());
        config.mining.serial_chip_count = Some(78);
        assert!(admitted_model_cutoff_c(&config, Model::S17e).is_err());
        config.mining.serial_chip_count = Some(135);
        config.mining.frequency_mhz = 531;
        assert!(admitted_model_cutoff_c(&config, Model::S17e).is_err());
        config.mining.frequency_mhz = 530;
        config.thermal.fan_max_pwm = 31;
        assert!(admitted_model_cutoff_c(&config, Model::S17e).is_err());
    }
    fn identity(target: &str) -> PlatformIdentitySnapshot {
        PlatformIdentitySnapshot {
            declared_board_target: Some(target.into()),
            observed_board_target: None,
            board_desc: dcentrald_common::BoardDesc::lookup(target),
            declared_platform_marker: Some("zynq-bm1396-stock".into()),
            declared_subtype: None,
            declared_psu_hardware_variant: None,
            observed_control_board: "offline declaration; no hardware opened".into(),
        }
    }
    fn configured() -> DcentraldConfig {
        let mut config: DcentraldConfig = toml::from_str(include_str!(
            "../../configs/beta/am2-t17e-baked-default.toml"
        ))
        .unwrap();
        config.validate().unwrap();
        assert!(admitted_cutoff_c(&config).is_err());
        config.pool.url = "stratum+tcp://127.0.0.1:3333".into();
        config.pool.worker = "offline.declaration".into();
        config.mining.enabled = true;
        config.validate().unwrap();
        config
    }
    fn protocol(config: &DcentraldConfig) -> AsicProtocolAdmission {
        crate::admit_board_desc_runtime_dispatch(
            identity("am2-t17e").board_desc,
            crate::RuntimeDispatchKind::Bm1396Native,
            config.mining_start_enabled(),
            crate::configured_asic_protocol_identity(config).unwrap(),
        )
        .unwrap()
        .require_asic_protocol(
            crate::RuntimeDispatchKind::Bm1396Native,
            "am2-t17e",
            AsicProtocolIdentity::Bm1396,
        )
        .unwrap()
    }
    #[test]
    fn baked_t17e_requires_exact_lifecycle_consumed_protocol_and_source_profile() {
        let config = configured();
        let exact = identity("am2-t17e");
        let admitted = admit(&exact, &config, protocol(&config)).unwrap();
        assert_eq!(admitted.model(), Model::T17e);
        assert_eq!(admitted.board_target(), "am2-t17e");
        assert_eq!(admitted.cutoff_c(), 75);
        let descriptor = exact.board_desc.unwrap();
        assert!(!descriptor.mining_default_enabled);
        assert!(matches!(
            descriptor.release_channel,
            dcentrald_common::ReleaseChannel::Beta
        ));
        assert!(matches!(
            descriptor.runtime_status,
            RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::Bm1396Native,
                generic_construction: GenericConstruction::Refused,
            }
        ));
        for dispatch in [
            crate::RuntimeDispatchKind::StandardDaemon,
            crate::RuntimeDispatchKind::Bm1391Native,
        ] {
            assert!(crate::admit_board_desc_runtime_dispatch(
                exact.board_desc,
                dispatch,
                true,
                crate::configured_asic_protocol_identity(&config).unwrap()
            )
            .is_err());
        }
        for target in [
            "am2-s17e",
            "am2-s17p",
            "am2-t17",
            "am2-t17plus",
            "am2-s19pro",
            "am1-t15",
            "am2-t17e-extra",
        ] {
            assert!(
                admit(&identity(target), &config, protocol(&config)).is_err(),
                "{target}"
            );
        }
        let mut foreign = identity("am2-t17e");
        foreign.declared_platform_marker = Some("zynq-bm1391-stock".into());
        assert!(admit(&foreign, &config, protocol(&config)).is_err());
        // An actual prior BM1396 protocol grant cannot bless a changed lifecycle.
        let mut changed = identity("am2-t17e");
        // The catalog is borrowed immutable data; mutate only a private test copy.
        let mut changed_descriptor = (*changed.board_desc.unwrap()).clone();
        changed_descriptor.runtime_status = RuntimeStatus::SpecialisedLifecycle {
            lane: LifecycleLane::Bm1391Native,
            generic_construction: GenericConstruction::Refused,
        };
        changed.board_desc = Some(Box::leak(Box::new(changed_descriptor)));
        assert!(admit(&changed, &config, protocol(&config)).is_err());
        let foreign_protocol = crate::admit_board_desc_runtime_dispatch(
            dcentrald_common::BoardDesc::lookup("am1-s15"),
            crate::RuntimeDispatchKind::Bm1391Native,
            true,
            Some(AsicProtocolIdentity::Bm1391),
        )
        .unwrap()
        .require_asic_protocol(
            crate::RuntimeDispatchKind::Bm1391Native,
            "am1-s15",
            AsicProtocolIdentity::Bm1391,
        )
        .unwrap();
        assert!(admit(&exact, &config, foreign_protocol)
            .unwrap_err()
            .contains("consumed protocol authority"));
        for defect in 0..16 {
            let mut defective = configured();
            match defect {
                0 => defective.mining.model = Some("s17e".into()),
                1 => defective.mining.serial_chip_type = Some("BM1397".into()),
                2 => defective.mining.serial_chip_count = Some(77),
                3 => defective.mining.frequency_mhz = 350,
                4 => defective.mining.voltage_mv = 21_000,
                5 => defective.mining.version_rolling = true,
                6 => defective.mining.passthrough = true,
                7 => defective.watchdog.enabled = false,
                8 => defective.thermal.dangerous_temp_c = 81,
                9 => defective.thermal.fan_min_pwm = 29,
                10 => defective.thermal.fan_max_pwm = 31,
                11 => defective.autotuner.enabled = true,
                12 => defective.hash_on_disconnect.enabled = true,
                13 => defective.donation.enabled = true,
                14 => defective.pool.protocol = Some("sv2".into()),
                15 => defective.mining.enabled = false,
                _ => unreachable!(),
            }
            assert!(
                admit(&exact, &defective, protocol(&config)).is_err(),
                "defect {defect}"
            );
        }
    }
}
