use dcentrald_common::runtime_hardware_recipe::{
    self, Am2HardwareFlag, HardwareRecipeProfile, PowerControlPolarity, RuntimeHardwareRecipe,
};
use dcentrald_common::BoardDesc;

fn am2(profile: HardwareRecipeProfile) -> RuntimeHardwareRecipe {
    RuntimeHardwareRecipe::resolve(
        BoardDesc::lookup("am2-s19j").unwrap(),
        "Zynq am2",
        "s19j-hybrid",
        profile,
    )
    .unwrap()
}

#[test]
fn shipped_transport_defaults_belong_to_exact_am2_composition() {
    let recipe = am2(HardwareRecipeProfile::BoardDefault);
    for name in [
        "DCENT_AM2_I2C_SLAVE_SAFE",
        "DCENT_AM2_DSPIC_BOSMINER_FAITHFUL",
        "DCENT_AM2_GET_VERSION_FRAMED_4B",
        "DCENT_AM2_PSU_BITBANG_USE_MMAP",
        "DCENT_AM2_EEPROM_BUS_WARMUP",
        "DCENT_AM2_MCR_OUT2",
        "DCENT_AM2_IER_BOSMINER_PARITY",
        "DCENT_BM1362_ENABLE_UART_RELAY_LAB",
        "DCENT_AM2_SKIP_FAST_UART",
        "DCENT_AM2_SKIP_115200_PER_CHIP",
        "DCENT_AM2_SERIAL_WORK_DISPATCH",
    ] {
        assert!(
            recipe.am2_flag(Am2HardwareFlag::from_env_name(name).unwrap()),
            "{name}"
        );
    }
    for name in [
        "DCENT_AM2_TRUST_RAIL_FALLBACK",
        "DCENT_AM2_PIC_RESET_AND_START_APP",
        "DCENT_AM2_ENERGIZE_ACCEPT_DEGRADED",
    ] {
        assert_eq!(
            Am2HardwareFlag::from_env_name(name),
            None,
            "diagnostic bypass {name} has no native default"
        );
    }
    assert_eq!(
        recipe.gpio907_polarity(),
        None,
        "generic AM2 never inherits .25 wiring"
    );
}

#[test]
fn carrier_route_descriptor_and_profile_mismatches_refuse() {
    let board = BoardDesc::lookup("am2-s19j").unwrap();
    for (carrier, route) in [
        ("Amlogic", "s19j-hybrid"),
        ("Zynq am2", "s17-hybrid"),
        ("Zynq am2", "standard-daemon"),
    ] {
        assert!(RuntimeHardwareRecipe::resolve(
            board,
            carrier,
            route,
            HardwareRecipeProfile::BoardDefault
        )
        .is_err());
    }
    let mut spoofed = board.clone();
    spoofed.asic_protocol = dcentrald_common::AsicProtocolIdentity::Bm1397;
    assert!(RuntimeHardwareRecipe::resolve(
        &spoofed,
        "Zynq am2",
        "s19j-hybrid",
        HardwareRecipeProfile::BoardDefault
    )
    .is_err());
    for target in ["am2-s17p", "am2-s19pro", "am3-s19k"] {
        assert!(RuntimeHardwareRecipe::resolve(
            BoardDesc::lookup(target).unwrap(),
            "Zynq am2",
            "s17-hybrid",
            HardwareRecipeProfile::Xil25Loki
        )
        .is_err());
    }
    assert!(RuntimeHardwareRecipe::resolve(
        board,
        "Zynq am2",
        "serial",
        HardwareRecipeProfile::BoardDefault
    )
    .is_ok());
}

#[test]
fn exact_s17_and_signed_xil25_profiles_have_native_active_low_cutoffs() {
    for target in ["am2-s17p", "am2-s17plus", "am2-t17", "am2-t17plus"] {
        let recipe = RuntimeHardwareRecipe::resolve(
            BoardDesc::lookup(target).unwrap(),
            "Zynq am2",
            "s17-hybrid",
            HardwareRecipeProfile::BoardDefault,
        )
        .unwrap();
        assert_eq!(
            recipe.gpio907_polarity(),
            Some(PowerControlPolarity::ActiveLow)
        );
        assert!(!recipe.am2_flag(Am2HardwareFlag::Bm1362UartRelay));
    }
    assert_eq!(
        am2(HardwareRecipeProfile::Xil25Loki).gpio907_polarity(),
        Some(PowerControlPolarity::ActiveLow)
    );
    for target in ["am2-s19pro", "am2-s19", "am2-t19", "am2-s19a", "am2-s19plus"] {
        let native = RuntimeHardwareRecipe::resolve(
            BoardDesc::lookup(target).unwrap(),
            "Zynq am2", "serial", HardwareRecipeProfile::BoardDefault,
        ).unwrap();
        assert_eq!(native.gpio907_polarity(), Some(PowerControlPolarity::ActiveLow), "{target}");
    }
    let unproved = RuntimeHardwareRecipe::resolve(
        BoardDesc::lookup("am2-s19i").unwrap(),
        "Zynq am2",
        "serial",
        HardwareRecipeProfile::BoardDefault,
    )
    .unwrap();
    assert_eq!(
        unproved.gpio907_polarity(),
        None,
        "S19i cannot inherit a sibling's polarity"
    );
}

#[test]
fn explicit_lab_polarity_cannot_fall_through_when_empty_or_conflicting() {
    use runtime_hardware_recipe::resolve_power_control_polarity as resolve;
    assert!(resolve(None, None).is_err());
    for declaration in [(false, false), (true, true)] {
        assert!(resolve(Some(PowerControlPolarity::ActiveLow), Some(declaration)).is_err());
    }
    assert_eq!(
        resolve(None, Some((true, false))).unwrap(),
        PowerControlPolarity::ActiveLow
    );
    assert_eq!(
        resolve(None, Some((false, true))).unwrap(),
        PowerControlPolarity::ActiveHigh
    );
    assert!(resolve(Some(PowerControlPolarity::ActiveLow), None)
        .unwrap()
        .off_level());
    assert!(!resolve(Some(PowerControlPolarity::ActiveHigh), None)
        .unwrap()
        .off_level());
}

#[test]
fn hardware_profile_parser_accepts_only_exact_signed_values() {
    for profile in [
        HardwareRecipeProfile::BoardDefault,
        HardwareRecipeProfile::Xil25Loki,
    ] {
        assert_eq!(
            profile.as_str().parse::<HardwareRecipeProfile>(),
            Ok(profile)
        );
    }
    for invalid in [
        "",
        "am2-xil-loki",
        "xil",
        "am2-s19j",
        " board-default",
        "BOARD-DEFAULT",
    ] {
        assert!(invalid.parse::<HardwareRecipeProfile>().is_err());
    }
}

#[test]
fn startup_recipe_is_installed_once_and_cannot_change_under_retained_owners() {
    const CHILD: &str = "DCENT_RECIPE_INSTALL_TEST_CHILD";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "startup_recipe_is_installed_once_and_cannot_change_under_retained_owners"
            ])
            .env(CHILD, "1")
            .status()
            .unwrap()
            .success());
        return;
    }
    assert!(runtime_hardware_recipe::installed().is_none());
    let recipe = am2(HardwareRecipeProfile::Xil25Loki);
    runtime_hardware_recipe::install(recipe).unwrap();
    assert!(runtime_hardware_recipe::install(recipe).is_err());
    assert!(runtime_hardware_recipe::install(am2(HardwareRecipeProfile::BoardDefault)).is_err());
    assert_eq!(
        runtime_hardware_recipe::gpio907_polarity(),
        Some(PowerControlPolarity::ActiveLow)
    );
}
