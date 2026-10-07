//! Move-only declaration admission for the exact retained S15/T15 runtime.
//! Physical fabric, current boot, GPIO and chip population are checked again
//! by the native owner before any source enable or work publication.
use crate::{config::DcentraldConfig, daemon_lifecycle::PlatformIdentitySnapshot};
use dcentrald_common::{AsicProtocolIdentity, BoardFamily, ChainTransportKind, WorkEngineKind};
use dcentrald_hal::platform::stock_bm1391::Model;

#[derive(Debug)]
#[must_use = "consume exact BM1391 admission in its native runtime"]
pub(crate) struct Bm1391DispatchAdmission {
    model: Model,
    board_target: &'static str,
}

impl Bm1391DispatchAdmission {
    pub(crate) fn model(&self) -> Model {
        self.model
    }
    pub(crate) fn board_target(&self) -> &'static str {
        self.board_target
    }
}

pub(crate) fn admit(
    identity: &PlatformIdentitySnapshot,
    config: &DcentraldConfig,
) -> Result<Bm1391DispatchAdmission, String> {
    let (model, model_key, count) = match identity.board_target() {
        "am1-s15" => (Model::S15, "s15", 72),
        "am1-t15" => (Model::T15, "t15", 60),
        _ => return Err("BM1391 native admission requires exact S15/T15 target".into()),
    };
    let desc = identity
        .board_desc
        .ok_or("BM1391 native BoardDesc missing")?;
    if desc.board_target != identity.board_target()
        || desc.family != BoardFamily::Zynq
        || desc.chain_transport != ChainTransportKind::StockFpga
        || desc.work_engine != WorkEngineKind::FpgaWorkFifo
        || desc.asic_protocol != AsicProtocolIdentity::Bm1391
        || identity.platform_marker() != "zynq-bm1391-stock"
    {
        return Err("BM1391 native composition or platform declaration disagrees".into());
    }
    if config.mining.model.as_deref() != Some(model_key)
        || crate::configured_asic_protocol_identity(config)? != Some(AsicProtocolIdentity::Bm1391)
        || config.mining.serial_chip_count != Some(count)
        || !config.mining_start_enabled()
        || config.mining.passthrough
        || !config.watchdog.enabled
    {
        return Err(
            "BM1391 requires exact model/population, native enabled mining and watchdog".into(),
        );
    }
    let frequency = config.mining.frequency_mhz;
    if !(100..=900).contains(&frequency)
        || frequency % 25 != 0
        || frequency == 575
        || !(16030..=20280).contains(&config.mining.voltage_mv)
        || config.thermal.dangerous_temp_c == 0
    {
        return Err(
            "BM1391 frequency/voltage/thermal configuration is outside its source profile".into(),
        );
    }
    Ok(Bm1391DispatchAdmission {
        model,
        board_target: desc.board_target,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(target: &str) -> PlatformIdentitySnapshot {
        PlatformIdentitySnapshot {
            declared_board_target: Some(target.into()),
            observed_board_target: None,
            board_desc: dcentrald_common::BoardDesc::lookup(target),
            declared_platform_marker: Some("zynq-bm1391-stock".into()),
            declared_subtype: None,
            declared_psu_hardware_variant: None,
            observed_control_board: "declaration fixture; no hardware opened".into(),
        }
    }

    #[test]
    fn both_exact_baked_profiles_activate_only_their_native_declaration() {
        for (target, source, model) in [
            (
                "am1-s15",
                include_str!("../../configs/beta/am1-s15-baked-default.toml"),
                Model::S15,
            ),
            (
                "am1-t15",
                include_str!("../../configs/beta/am1-t15-baked-default.toml"),
                Model::T15,
            ),
        ] {
            let mut config: DcentraldConfig = toml::from_str(source).unwrap();
            config.validate().unwrap();
            assert!(admit(&identity(target), &config).is_err());
            config.pool.url = "stratum+tcp://127.0.0.1:3333".into();
            config.pool.worker = "offline.declaration".into();
            config.mining.enabled = true;
            config.validate().unwrap();
            let admitted = admit(&identity(target), &config).unwrap();
            assert_eq!(admitted.model(), model);
            assert_eq!(admitted.board_target(), target);
            let protocol = crate::configured_asic_protocol_identity(&config).unwrap();
            let generic = crate::admit_board_desc_runtime_dispatch(
                identity(target).board_desc,
                crate::RuntimeDispatchKind::Bm1391Native,
                true,
                protocol,
            )
            .unwrap();
            generic
                .require_asic_protocol(
                    crate::RuntimeDispatchKind::Bm1391Native,
                    target,
                    AsicProtocolIdentity::Bm1391,
                )
                .unwrap();
            for foreign in [
                "am1-s9se",
                "am2-s17p",
                if target == "am1-s15" {
                    "am1-t15"
                } else {
                    "am1-s15"
                },
            ] {
                assert!(admit(&identity(foreign), &config).is_err());
            }
            let mut foreign_platform = identity(target);
            foreign_platform.declared_platform_marker = Some("zynq-bm1-s9".into());
            assert!(admit(&foreign_platform, &config).is_err());
            config.mining.serial_chip_type = Some("BM1362".into());
            assert!(admit(&identity(target), &config).is_err());
            config.mining.serial_chip_type = Some("BM1391".into());
            config.mining.frequency_mhz = 575;
            assert!(admit(&identity(target), &config).is_err());
            config.mining.frequency_mhz = 100;
            config.watchdog.enabled = false;
            assert!(admit(&identity(target), &config).is_err());
        }
    }
}
