use super::*;

fn four_site_health(model: Model) -> (Health, Profile) {
    let positions = if model == Model::S15 {
        [18, 13, 54, 49]
    } else {
        [15, 11, 45, 41]
    };
    let sensors: Vec<_> = (0..3)
        .flat_map(|chain| {
            positions.map(|position| ThermalSensor {
                chain,
                chip_address: (position - 1) * model.address_interval(),
                sensor_address: 0x98,
                manufacturer: 0x1a,
            })
        })
        .collect();
    let mut health = Health::default();
    health
        .bind_thermal_sensors(sensors.clone(), &[0, 1, 2])
        .unwrap();
    health.temperatures = sensors
        .into_iter()
        .map(|sensor| BoardTemperature {
            sensor,
            raw_extended: 104,
            pcb_celsius: 40,
            estimated_chip_celsius: 55,
            observed_at: Instant::now(),
            bridge_reply: dcentrald_common::bm1391_stock_return::Bm1391StockRegisterReturn {
                chain_slot: sensor.chain,
                register: 0x1c,
                chip_address: sensor.chip_address,
                crc5: 0,
                register_type: 0,
                value: 104,
                fpga_crc_error: false,
            },
        })
        .collect();
    health.require_temperature = true;
    (
        health,
        Profile {
            model,
            configured_mhz: 400,
            working_volts: 20.0,
            pll: PllSetting::new(2800, 7).unwrap(),
            timeout_ticks: 100,
            cutoff_c: 85,
        },
    )
}
#[test]
fn retained_four_sensor_topology_accepts_all_source_sites_in_any_sample_order() {
    for model in [Model::S15, Model::T15] {
        let (mut health, profile) = four_site_health(model);
        assert_eq!(health.temperatures.len(), 12);
        health.check_temperatures(profile, &[0, 1, 2]).unwrap();
        health.temperatures.reverse();
        health.check_temperatures(profile, &[0, 1, 2]).unwrap();
        assert!(health
            .bind_thermal_sensors(health.thermal_sensors.clone(), &[0, 1, 2])
            .is_err());
    }
}
#[test]
fn retained_thermal_topology_refuses_missing_duplicate_foreign_stale_or_hot_sites() {
    for model in [Model::S15, Model::T15] {
        let (health, profile) = four_site_health(model);
        for index in 0..12 {
            let mut missing = health.clone();
            missing.temperatures.remove(index);
            assert!(missing.check_temperatures(profile, &[0, 1, 2]).is_err());
            let mut duplicate = health.clone();
            duplicate.temperatures[index] = duplicate.temperatures[(index + 1) % 12];
            assert!(duplicate.check_temperatures(profile, &[0, 1, 2]).is_err());
            let mut foreign = health.clone();
            foreign.temperatures[index].sensor.chain = 3;
            assert!(foreign.check_temperatures(profile, &[0, 1, 2]).is_err());
            let mut stale = health.clone();
            stale.temperatures[index].observed_at = Instant::now() - Duration::from_secs(9);
            assert!(stale.check_temperatures(profile, &[0, 1, 2]).is_err());
            let mut hot = health.clone();
            hot.temperatures[index].estimated_chip_celsius = profile.cutoff_c;
            assert!(hot.check_temperatures(profile, &[0, 1, 2]).is_err());
        }
        let sensors = health.thermal_sensors.clone();
        let mut duplicates = sensors.clone();
        duplicates[1] = duplicates[0];
        duplicates[1].manufacturer = 0x41; // identity duplicate despite different manufacturer
        assert!(Health::default()
            .bind_thermal_sensors(duplicates, &[0, 1, 2])
            .is_err());
        assert!(Health::default()
            .bind_thermal_sensors(sensors[..4].to_vec(), &[0, 1, 2])
            .is_err());
        assert!(Health::default()
            .bind_thermal_sensors(sensors, &[0, 1])
            .is_err());
        assert!(health.check_temperatures(profile, &[0, 1, 2, 3]).is_err());
    }
}
