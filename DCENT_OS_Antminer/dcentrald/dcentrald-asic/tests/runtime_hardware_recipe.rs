use dcentrald_common::runtime_hardware_recipe::{
    self, HardwareRecipeProfile, RuntimeHardwareRecipe,
};

#[test]
fn captured_native_dspic_default_and_lab_override_keep_original_parser() {
    const CHILD: &str = "DCENT_DSPIC_RECIPE_TEST_CHILD";
    const ENV: &str = "DCENT_AM2_DSPIC_BOSMINER_FAITHFUL";
    let cases = [
        ("absent", None, true),
        ("strict_truthy", Some("true"), false),
        ("one", Some(" 1 "), true),
        ("false", Some("0"), false),
        ("invalid", Some(" true "), false),
    ];
    if let Ok(case) = std::env::var(CHILD) {
        let recipe = RuntimeHardwareRecipe::resolve(
            dcentrald_common::BoardDesc::lookup("am2-s19j").unwrap(),
            "Zynq am2",
            "s19j-hybrid",
            HardwareRecipeProfile::BoardDefault,
        )
        .unwrap();
        runtime_hardware_recipe::install(recipe).unwrap();
        let expected = cases.iter().find(|row| row.0 == case).unwrap().2;
        assert_eq!(
            dcentrald_asic::dspic::dspic_bosminer_faithful_enabled(),
            !dcentrald_common::lab_env::compiled() || expected
        );
        return;
    }
    for (name, value, _) in cases {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "captured_native_dspic_default_and_lab_override_keep_original_parser",
            ])
            .env(CHILD, name)
            .env_remove(ENV);
        if let Some(value) = value {
            child.env(ENV, value);
        }
        assert!(child.status().unwrap().success(), "{name}");
    }
}
