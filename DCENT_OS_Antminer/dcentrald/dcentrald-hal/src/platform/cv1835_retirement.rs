//! Refusal for the retired CV1835 implementation before any hardware owner.
//! Held stock ABI and reverse-engineering fixtures remain test-only in
//! `cvitek_stock_evidence`; they do not provide a complete mining lifecycle.

use crate::{HalError, Result};

/// The held stock root compatible is linux,dummy-virt and it has no model.
/// These exact child-node compatibles identify its CV1835 controller without
/// relying on the optional uart_trans module or touching a device endpoint.
pub(crate) fn cv1835_child_identity(root: &std::path::Path) -> bool {
    [
        (
            "clock-controller/compatible",
            b"cvitek,cv1835-clk".as_slice(),
        ),
        (
            "pinctrl@3001000/compatible",
            b"cvitek,pinctrl-cv1835".as_slice(),
        ),
        (
            "cv-emmc@4300000/compatible",
            b"cvitek,cv1835-emmc".as_slice(),
        ),
    ]
    .iter()
    .any(|(path, expected)| {
        std::fs::read(root.join(path))
            .map(|bytes| bytes.split(|b| *b == 0).any(|value| value == *expected))
            .unwrap_or(false)
    })
}

pub(crate) fn require_supported_controller(
    cpuinfo: &str,
    compatible: &str,
    model: &str,
    uart_trans_loaded: bool,
    cv1835_children: bool,
) -> Result<()> {
    if cv1835_children
        || [cpuinfo, compatible, model]
            .iter()
            .any(|value| value.to_ascii_lowercase().contains("cv1835"))
    {
        return Err(HalError::Platform(
            "CV1835 is Unsupported: the incomplete runtime was retired; held stock evidence is retained for future implementation".into(),
        ));
    }
    // uart_trans exists on several SoCs. Its name cannot authorize CV1835
    // GPIOs or justify falling through to the Amlogic ttyS convention.
    if uart_trans_loaded && super::classify_soc_evidence(cpuinfo, compatible).is_none() {
        return Err(HalError::Platform(
            "uart_trans controller identity is unknown; refusing hardware ownership".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn held_dtb_children_refuse_generic_root_without_loaded_module() {
        use std::io::Write;
        let fdt = super::super::cvitek_stock_evidence::parse_fdt(include_bytes!(
            "../../../../br2_external_dcentos/board/cvitek/r16-stock-evidence/fixtures/fdt_cv1835_miner_emmc.dtb"
        ))
        .expect("held stock DTB parses");
        let root_node = fdt.node("/").expect("held root node");
        let compatible = root_node.prop_str("compatible").expect("root compatible");
        assert_eq!(compatible, "linux,dummy-virt");
        assert!(root_node.prop_str("model").is_none());
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "dcent-cv1835-child-identity-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        assert!(!cv1835_child_identity(&root));
        for path in ["/clock-controller", "/pinctrl@3001000", "/cv-emmc@4300000"] {
            let node = fdt.node(path).expect("exact held child path");
            let bytes = &node
                .props
                .iter()
                .find(|(name, _)| name == "compatible")
                .expect("held child compatible")
                .1;
            let directory = root.join(path.trim_start_matches('/'));
            std::fs::create_dir(&directory).unwrap();
            let property = directory.join("compatible");
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&property)
                .unwrap();
            file.write_all(bytes).unwrap();
            drop(file);
            assert!(cv1835_child_identity(&root), "held child {path}");
            assert!(require_supported_controller(
                "",
                &compatible,
                "",
                false,
                cv1835_child_identity(&root)
            )
            .is_err());
            // Remove only these exact inert fixture entries; never recurse.
            std::fs::remove_file(&property).unwrap();
            std::fs::remove_dir(&directory).unwrap();
            assert!(!cv1835_child_identity(&root));
        }
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn cv1835_identity_refuses_with_or_without_uart_trans() {
        for module in [false, true] {
            for (cpu, compatible, model) in [
                ("Hardware: CV1835", "", ""),
                ("", "cvitek,cv1835", ""),
                ("", "", "Sophgo CV1835"),
                ("Hardware: AM33XX", "cvitek,cv1835", ""),
            ] {
                assert!(
                    require_supported_controller(cpu, compatible, model, module, false).is_err()
                );
            }
            assert!(
                require_supported_controller("", "linux,dummy-virt", "", module, true).is_err()
            );
        }
    }

    #[test]
    fn shared_module_is_not_a_controller_identity() {
        assert!(require_supported_controller("", "", "", true, false).is_err());
        for (cpu, compatible) in [
            ("Hardware\t: AM33XX", "ti,am335x-bone-black"),
            ("", "amlogic,meson-axg"),
            ("", "xlnx,zynq-7000"),
        ] {
            assert!(require_supported_controller(cpu, compatible, "", true, false).is_ok());
        }
        assert!(require_supported_controller("", "", "", false, false).is_ok());
    }
}
