//! Exact AM33XX APW supply ownership, separate from the historical GPIO59 label.
//!
//! Held LuxOS ELF SHA256 386b88490154b1007ca15d0f529749664ec641743d7f132127ec078c196df1df:
//! enum formatter0x5e8f80 maps1 to AM33XX; semantic PSU ON/OFF0x5fb9f8 selects65,
//! active_low=false, ON1/OFF0. Initializer0x604720 emits opcode83 DAC0. May12
//! lux.ftrace2 lines91071-91072 independently join GPIO65 and that exact frame.
//! This is software/held warm-trace evidence, not a measured cold rail result.

use std::path::{Path, PathBuf};

use crate::{HalError, Result};

pub const PSU_ENABLE_GPIO: u32 = 65;
pub const PSU_FIXED_MILLIVOLTS: u16 = 15_120;
pub const PSU_BUS: u8 = 1;

/// A read-only join to the running kernel's exact controller and adapter.
/// Board metadata alone never constructs this value. The normal constructor
/// verifies model, GPIO controller reg/base/count and the adapter's DT pins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BbPsuControllerBinding {
    gpio_root: PathBuf,
    i2c_root: PathBuf,
    dt_root: PathBuf,
    supply_controller: PathBuf,
    bus_controller: PathBuf,
    adapter_node: PathBuf,
}

fn refusal(detail: impl std::fmt::Display) -> HalError {
    HalError::Platform(format!("AM33XX PSU controller admission: {detail}"))
}

fn bytes(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|error| refusal(format!("{}: {error}", path.display())))
}

fn cells(path: &Path) -> Result<Vec<u32>> {
    let data = bytes(path)?;
    if data.is_empty() || data.len() % 4 != 0 {
        return Err(refusal(format!(
            "{} is not a DT cell array",
            path.display()
        )));
    }
    Ok(data
        .chunks_exact(4)
        .map(|cell| u32::from_be_bytes(cell.try_into().expect("four-byte chunk")))
        .collect())
}

fn has_token(path: &Path, expected: &[u8]) -> Result<bool> {
    Ok(bytes(path)?
        .split(|byte| *byte == 0)
        .any(|token| token == expected))
}

fn decimal(path: &Path) -> Result<u32> {
    std::fs::read_to_string(path)
        .map_err(refusal)?
        .trim()
        .parse()
        .map_err(refusal)
}

fn controller(gpio_root: &Path, base: u32, register: u32) -> Result<PathBuf> {
    let mut found = None;
    for entry in std::fs::read_dir(gpio_root).map_err(refusal)? {
        let entry = entry.map_err(refusal)?;
        if !entry.file_name().to_string_lossy().starts_with("gpiochip") {
            continue;
        }
        let path = entry.path();
        if decimal(&path.join("base"))? != base {
            continue;
        }
        if found.is_some() || decimal(&path.join("ngpio"))? != 32 {
            return Err(refusal("duplicate or mismatched GPIO bank"));
        }
        let node = path.join("device/of_node");
        if !has_token(&node.join("compatible"), b"ti,omap4-gpio")?
            || cells(&node.join("reg"))? != [register, 0x1000]
            || cells(&node.join("#gpio-cells"))? != [2]
        {
            return Err(refusal("GPIO owner is not the exact AM335x bank"));
        }
        found = Some(std::fs::canonicalize(node).map_err(refusal)?);
    }
    found.ok_or_else(|| refusal(format!("GPIO bank at base{base} is absent")))
}

fn adapter_node(i2c_root: &Path) -> Result<PathBuf> {
    let adapter = std::fs::canonicalize(i2c_root.join("i2c-1/device")).map_err(refusal)?;
    // Kernels place the adapter below its platform device. Bound the walk;
    // an unrelated ancestor may not supply a substitute DT identity.
    for parent in adapter.ancestors().take(3) {
        let node = parent.join("of_node");
        if node.exists() {
            if !has_token(&node.join("compatible"), b"i2c-gpio")? {
                return Err(refusal("PSU adapter is not i2c-gpio"));
            }
            let driver = std::fs::canonicalize(parent.join("driver")).map_err(refusal)?;
            if driver.file_name().and_then(|name| name.to_str()) != Some("i2c-gpio") {
                return Err(refusal("PSU adapter driver does not own i2c-gpio"));
            }
            return std::fs::canonicalize(node).map_err(refusal);
        }
    }
    Err(refusal("PSU adapter has no owned DT node"))
}

impl BbPsuControllerBinding {
    pub fn observe_system() -> Result<Self> {
        Self::observe_at(
            Path::new("/sys/class/gpio"),
            Path::new("/sys/class/i2c-dev"),
            Path::new("/proc/device-tree"),
        )
    }

    fn observe_at(gpio_root: &Path, i2c_root: &Path, dt_root: &Path) -> Result<Self> {
        use super::beaglebone::{S19J_IO_BOARD_V2_0_DT_COMPATIBLE, S19J_IO_BOARD_V2_0_DT_MODEL};
        if !has_token(
            &dt_root.join("compatible"),
            S19J_IO_BOARD_V2_0_DT_COMPATIBLE.as_bytes(),
        )? || bytes(&dt_root.join("model"))?.strip_suffix(&[0])
            != Some(S19J_IO_BOARD_V2_0_DT_MODEL.as_bytes())
        {
            return Err(refusal("exact S19J_IO_BOARD_V2_0 device tree is required"));
        }
        // Held controller roster: gpio0=44e07000 and gpio2=481ac000.
        // Never infer Linux global65 on a kernel with different bank bases.
        let supply_controller = controller(gpio_root, 64, 0x481a_c000)?;
        let bus_controller = controller(gpio_root, 0, 0x44e0_7000)?;
        let phandle = cells(&bus_controller.join("phandle"))?;
        if phandle.len() != 1 || phandle[0] == 0 {
            return Err(refusal("GPIO bus controller has no unique phandle"));
        }
        let adapter_node = adapter_node(i2c_root)?;
        let pins = if adapter_node.join("gpios").exists() {
            cells(&adapter_node.join("gpios"))?
        } else {
            let mut pins = cells(&adapter_node.join("sda-gpios"))?;
            pins.extend(cells(&adapter_node.join("scl-gpios"))?);
            pins
        };
        if pins != [phandle[0], 4, 0, phandle[0], 5, 0] {
            return Err(refusal(
                "PSU adapter must use raw GPIO0:4 SDA and GPIO0:5 SCL",
            ));
        }
        Ok(Self {
            gpio_root: gpio_root.to_path_buf(),
            i2c_root: i2c_root.to_path_buf(),
            dt_root: dt_root.to_path_buf(),
            supply_controller,
            bus_controller,
            adapter_node,
        })
    }

    /// Recheck the same objects before an ON or protocol mutation. Terminal
    /// cutoff itself uses preopened descriptors and does not depend on this
    /// potentially failing filesystem observation.
    pub fn revalidate(&self) -> Result<()> {
        if Self::observe_at(&self.gpio_root, &self.i2c_root, &self.dt_root)? != *self {
            return Err(refusal("controller or adapter identity changed"));
        }
        Ok(())
    }

    pub fn gpio(&self) -> u32 {
        PSU_ENABLE_GPIO
    }
    pub fn bus(&self) -> u8 {
        PSU_BUS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(std::path::PathBuf);

    impl Fixture {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            // Exact inert fixture roster only; never traverse or recursively
            // remove a tree that could contain a mount or replacement link.
            for file in [
                "dt/compatible",
                "dt/model",
                "board_target",
                "gpio/export",
                "i2c/i2c-1/device/driver",
                "i2c/i2c-1/device/of_node/compatible",
                "i2c/i2c-1/device/of_node/gpios",
                "i2c/i2c-1/device/of_node/sda-gpios",
                "i2c/i2c-1/device/of_node/scl-gpios",
            ] {
                let _ = std::fs::remove_file(self.0.join(file));
            }
            for bank in [0, 64] {
                let base = self.0.join(format!("gpio/gpiochip{bank}"));
                for file in [
                    "base",
                    "ngpio",
                    "device/of_node/compatible",
                    "device/of_node/reg",
                    "device/of_node/#gpio-cells",
                    "device/of_node/phandle",
                ] {
                    let _ = std::fs::remove_file(base.join(file));
                }
                for directory in ["device/of_node", "device", ""] {
                    let _ = std::fs::remove_dir(base.join(directory));
                }
            }
            for directory in [
                "i2c/i2c-1/device/of_node",
                "i2c/i2c-1/device",
                "i2c/i2c-1",
                "i2c",
                "drivers/i2c-gpio",
                "drivers",
                "dt",
                "gpio",
                "",
            ] {
                let _ = std::fs::remove_dir(self.0.join(directory));
            }
        }
    }

    fn write(root: &Path, path: &str, data: impl AsRef<[u8]>) {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, data).unwrap();
    }

    fn be(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_be_bytes()).collect()
    }

    fn fixture() -> Fixture {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = Fixture(std::env::temp_dir().join(format!(
            "dcent-bb-psu-binding-{}-{nonce}",
            std::process::id()
        )));
        std::fs::create_dir(root.path()).unwrap();
        write(
            root.path(),
            "dt/compatible",
            b"ti,am335x-bone-black\0ti,am335x\0",
        );
        write(
            root.path(),
            "dt/model",
            b"BeagleBone_Black_v2.1 on S19J_IO_BOARD_V2_0\0",
        );
        for (base, reg, phandle) in [(0, 0x44e0_7000, 19), (64, 0x481a_c000, 21)] {
            let bank = format!("gpio/gpiochip{base}");
            write(root.path(), &format!("{bank}/base"), base.to_string());
            write(root.path(), &format!("{bank}/ngpio"), b"32\n");
            write(
                root.path(),
                &format!("{bank}/device/of_node/compatible"),
                b"ti,omap4-gpio\0",
            );
            write(
                root.path(),
                &format!("{bank}/device/of_node/reg"),
                be(&[reg, 0x1000]),
            );
            write(
                root.path(),
                &format!("{bank}/device/of_node/#gpio-cells"),
                be(&[2]),
            );
            write(
                root.path(),
                &format!("{bank}/device/of_node/phandle"),
                be(&[phandle]),
            );
        }
        write(
            root.path(),
            "i2c/i2c-1/device/of_node/compatible",
            b"i2c-gpio\0",
        );
        write(
            root.path(),
            "i2c/i2c-1/device/of_node/gpios",
            be(&[19, 4, 0, 19, 5, 0]),
        );
        std::fs::create_dir_all(root.path().join("drivers/i2c-gpio")).unwrap();
        std::os::unix::fs::symlink(
            root.path().join("drivers/i2c-gpio"),
            root.path().join("i2c/i2c-1/device/driver"),
        )
        .unwrap();
        root
    }

    fn observe(root: &Path) -> Result<BbPsuControllerBinding> {
        BbPsuControllerBinding::observe_at(&root.join("gpio"), &root.join("i2c"), &root.join("dt"))
    }

    #[test]
    fn reconstructed_kernel_fixture_binds_psu65_and_both_dt_adapter_forms() {
        let root = fixture();
        let binding = observe(root.path()).unwrap();
        assert_eq!((binding.gpio(), binding.bus()), (65, 1));
        binding.revalidate().unwrap();
        std::fs::remove_file(root.path().join("i2c/i2c-1/device/of_node/gpios")).unwrap();
        write(
            root.path(),
            "i2c/i2c-1/device/of_node/sda-gpios",
            be(&[19, 4, 0]),
        );
        write(
            root.path(),
            "i2c/i2c-1/device/of_node/scl-gpios",
            be(&[19, 5, 0]),
        );
        observe(root.path()).unwrap();
    }

    #[test]
    fn foreign_model_roster_or_adapter_refuses_without_any_gpio_output() {
        let mutations: Vec<(&str, Vec<u8>)> = vec![
            ("dt/model", b"TI AM335x BeagleBone BTM\0".to_vec()),
            ("dt/compatible", b"ti,am335x-bone-black-sibling\0".to_vec()),
            ("gpio/gpiochip64/base", b"32".to_vec()),
            ("gpio/gpiochip64/ngpio", b"64".to_vec()),
            (
                "gpio/gpiochip64/device/of_node/compatible",
                b"ti,omap3-gpio\0".to_vec(),
            ),
            (
                "gpio/gpiochip64/device/of_node/reg",
                be(&[0x4804_c000, 0x1000]),
            ),
            (
                "gpio/gpiochip0/device/of_node/reg",
                be(&[0x481a_c000, 0x1000]),
            ),
            ("gpio/gpiochip0/device/of_node/#gpio-cells", be(&[3])),
            ("gpio/gpiochip0/device/of_node/phandle", be(&[0])),
            (
                "i2c/i2c-1/device/of_node/compatible",
                b"ti,omap4-i2c\0".to_vec(),
            ),
            ("i2c/i2c-1/device/of_node/gpios", be(&[21, 4, 0, 21, 5, 0])),
            ("i2c/i2c-1/device/of_node/gpios", be(&[19, 5, 0, 19, 4, 0])),
            ("i2c/i2c-1/device/of_node/gpios", be(&[19, 4, 1, 19, 5, 0])),
            ("i2c/i2c-1/device/of_node/gpios", vec![0, 1, 2]),
        ];
        for (path, value) in mutations {
            let root = fixture();
            let prior = observe(root.path()).unwrap();
            write(root.path(), "gpio/export", b"untouched");
            write(root.path(), path, value);
            assert!(observe(root.path()).is_err(), "{path}");
            assert!(prior.revalidate().is_err(), "{path}");
            assert_eq!(
                std::fs::read(root.path().join("gpio/export")).unwrap(),
                b"untouched"
            );
            assert!(!root.path().join("gpio/gpio65").exists());
        }
    }

    #[test]
    fn absent_owner_and_driver_refuse_even_with_correct_board_marker() {
        for path in [
            "gpio/gpiochip64/base",
            "i2c/i2c-1/device/driver",
            "gpio/gpiochip0/device/of_node/phandle",
        ] {
            let root = fixture();
            write(root.path(), "board_target", b"am3-bb-s19jpro\n");
            std::fs::remove_file(root.path().join(path)).unwrap();
            assert!(observe(root.path()).is_err(), "{path}");
        }
    }
}
