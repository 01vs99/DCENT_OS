use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::SeqCst);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("bm1396-native-{}-{stamp}-{id}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, bytes: &[u8]) {
        let path = self.0.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    fn tree(&self) {
        for name in [
            "#address-cells",
            "#size-cells",
            "reserved-memory/#address-cells",
            "reserved-memory/#size-cells",
        ] {
            self.write(name, &1u32.to_be_bytes());
        }
        self.write("memory@0/reg", &[0, 0, 0, 0, 0x10, 0, 0, 0]);
        self.write("reserved-memory/ranges", &[]);
        self.write(&format!("{DMA_NODE}/reg"), &[0x0f, 0, 0, 0, 1, 0, 0, 0]);
        self.write(
            &format!("{DMA_NODE}/compatible"),
            b"dcent,bm1396-stock-fpga-dma\0",
        );
        self.write(&format!("{DMA_NODE}/no-map"), &[]);
    }
    fn uid(&self) -> u32 {
        std::fs::metadata(&self.0).unwrap().uid()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Only this fresh unique test directory is removed, never a supplied
        // path, real kernel tree, mapping, image or existing workspace directory.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn receipt_binds_exact_r06_programming_current_boot_and_model() {
    let boot = "12345678-1234-1234-1234-123456789abc";
    for model in [Model::S17e, Model::T17e] {
        let mut receipt = FabricReceipt {
            schema: 1,
            boot_id: boot.into(),
            board_target: board_target(model).into(),
            bitstream_sha256: BITSTREAM_SHA256.into(),
            load_completed: true,
            prog_done: true,
        };
        assert!(
            validate_receipt(&receipt, boot, board_target(model), BITSTREAM_SHA256, model).is_ok()
        );
        receipt.prog_done = false;
        assert!(
            validate_receipt(&receipt, boot, board_target(model), BITSTREAM_SHA256, model).is_err()
        );
        receipt.prog_done = true;
        assert!(
            validate_receipt(&receipt, "", board_target(model), BITSTREAM_SHA256, model).is_err()
        );
        assert!(validate_receipt(&receipt, boot, "am1-s15", BITSTREAM_SHA256, model).is_err());
        assert!(validate_receipt(
            &receipt,
            boot,
            board_target(model),
            super::super::super::stock_bm1391::BITSTREAM_SHA256,
            model
        )
        .is_err());
    }
    assert!(serde_json::from_str::<FabricReceipt>(r#"{"schema":1,"boot_id":"x","board_target":"am2-s17e","bitstream_sha256":"x","load_completed":true,"prog_done":true,"extra":1}"#).is_err());
}

#[test]
fn protected_identity_refuses_symlink_writable_or_oversized_input() {
    let dir = Fixture::new();
    dir.write("identity", b"exact");
    assert_eq!(
        protected(&dir.0.join("identity"), 5, dir.uid()).unwrap(),
        b"exact"
    );
    assert!(protected(&dir.0.join("identity"), 4, dir.uid()).is_err());
    symlink(dir.0.join("identity"), dir.0.join("link")).unwrap();
    assert!(protected(&dir.0.join("link"), 10, dir.uid()).is_err());
    std::fs::set_permissions(
        dir.0.join("identity"),
        std::fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert!(protected(&dir.0.join("identity"), 10, dir.uid()).is_err());
}

#[test]
fn actual_directory_tree_requires_exact_unaliased_no_map_reservation() {
    let dir = Fixture::new();
    dir.tree();
    assert!(validate_dma_tree(&dir.0, dir.uid()).is_ok());
    dir.write(&format!("{DMA_NODE}/no-map"), &[0]);
    assert!(validate_dma_tree(&dir.0, dir.uid()).is_err());
    dir.write(&format!("{DMA_NODE}/no-map"), &[]);
    dir.write(
        "reserved-memory/other@f000000/reg",
        &[0x0f, 0, 0, 0, 0, 0, 0x10, 0],
    );
    assert!(validate_dma_tree(&dir.0, dir.uid()).is_err());
    dir.write(
        "reserved-memory/other@f000000/reg",
        &[0x0e, 0, 0, 0, 0, 0, 0x10, 0],
    );
    assert!(validate_dma_tree(&dir.0, dir.uid()).is_ok());
    dir.write(&format!("{DMA_NODE}/reusable"), &[]);
    assert!(validate_dma_tree(&dir.0, dir.uid()).is_err());
}

#[test]
fn current_kernel_mapping_flags_and_visible_system_ram_are_required() {
    let config = b"CONFIG_MMU=y\nCONFIG_ARCH_ZYNQ=y\nCONFIG_CPU_V7=y\nCONFIG_HAVE_ARCH_PFN_VALID=y\nCONFIG_ARM_DMA_MEM_BUFFERABLE=y\n# CONFIG_ARM_LPAE is not set\n";
    assert!(validate_kernel(KERNEL_RELEASE, config).is_ok());
    assert!(validate_kernel("5.4.242", config).is_err());
    assert!(validate_kernel(KERNEL_RELEASE, &config[..config.len() - 35]).is_err());
    assert!(
        validate_iomem("00000000-0effffff : System RAM\n 00008000-008fffff : Kernel code\n")
            .is_ok()
    );
    assert!(validate_iomem("00000000-0fffffff : System RAM\n").is_err());
    assert!(validate_iomem("00000000-00000000 : System RAM\n").is_err());
    assert!(validate_iomem("").is_err());
}

#[test]
fn retained_mapping_unmaps_exact_host_fixture_without_physical_access() {
    let dir = Fixture::new();
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(dir.0.join("mapping"))
        .unwrap();
    file.set_len(4096).unwrap();
    let mapping = Mapping::new(&file, 0, 4096).unwrap();
    // SAFETY: fixture-backed live mmap, aligned first word within its 4096 bytes.
    unsafe {
        std::ptr::write_volatile(mapping.pointer as *mut u32, 0x12345678);
    }
    drop(mapping);
    let bytes = std::fs::read(dir.0.join("mapping")).unwrap();
    assert_eq!(&bytes[..4], &0x12345678u32.to_ne_bytes());
}
