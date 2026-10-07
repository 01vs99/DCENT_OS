//! Current-boot DDR reservation for the exact 256-MiB native image profile.
use super::*;
use std::path::Path;

pub const DMA_BASE: u32 = 0x0f00_0000;
pub const DMA_BYTES: u32 = 0x0100_0000;
const NODE: &str = "reserved-memory/bm1391-dma@f000000";

/// A checked kernel device-tree reservation, retained by the native mapping.
/// The private fields prevent an ordinary caller from minting an unchecked
/// address. It is not an allocation from Linux's general-purpose RAM pool.
#[derive(Debug, Clone, Copy)]
pub struct DmaReservation {
    base: u32,
    bytes: u32,
}
impl DmaReservation {
    pub fn physical_base(self) -> u32 {
        self.base
    }
    pub fn bytes(self) -> u32 {
        self.bytes
    }

    pub(super) fn observe_kernel_tree(root: &Path) -> Result<Self, String> {
        Self::observe_tree(root, 0)
    }

    fn observe_tree(root: &Path, expected_uid: u32) -> Result<Self, String> {
        fn read_property(
            root: &Path,
            name: &str,
            maximum: usize,
            expected_uid: u32,
        ) -> Result<Vec<u8>, String> {
            use std::io::Read;
            let path = root.join(name);
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)
                .map_err(|e| format!("BM1391 DMA {}: {e}", path.display()))?;
            let info = file.metadata().map_err(|e| e.to_string())?;
            if !info.is_file() || info.mode() & 0o022 != 0 || info.uid() != expected_uid {
                return Err(
                    "BM1391 DMA kernel property has unsafe ownership or permissions".into(),
                );
            }
            let mut bytes = Vec::new();
            file.by_ref()
                .take(maximum as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() > maximum {
                return Err("BM1391 DMA kernel property is oversized".into());
            }
            Ok(bytes)
        }
        let read = |root: &Path, name: &str, maximum: usize| {
            read_property(root, name, maximum, expected_uid)
        };
        let one = 1u32.to_be_bytes();
        for name in [
            "#address-cells",
            "#size-cells",
            "reserved-memory/#address-cells",
            "reserved-memory/#size-cells",
        ] {
            if read(root, name, 4)? != one {
                return Err("BM1391 DMA kernel address/size cells mismatch".into());
            }
        }
        if read(root, "memory@0/reg", 8)? != [0, 0, 0, 0, 0x10, 0, 0, 0]
            || !read(root, "reserved-memory/ranges", 0)?.is_empty()
            || read(root, &format!("{NODE}/reg"), 8)? != [0x0f, 0, 0, 0, 1, 0, 0, 0]
            || read(root, &format!("{NODE}/compatible"), 64)? != b"dcent,bm1391-stock-fpga-dma\0"
            || !read(root, &format!("{NODE}/no-map"), 0)?.is_empty()
            || root.join(NODE).join("reusable").exists()
            || root.join(NODE).join("status").exists()
        {
            return Err(
                "BM1391 exact enabled non-reusable no-map DDR reservation is missing".into(),
            );
        }
        Ok(Self {
            base: DMA_BASE,
            bytes: DMA_BYTES,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;

    struct FixtureDirectory(PathBuf);
    impl FixtureDirectory {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for FixtureDirectory {
        fn drop(&mut self) {
            // This exact directory was created exclusively by fixture(); no
            // caller-supplied source or shared staging path is removed.
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn observe(root: &Path) -> Result<DmaReservation, String> {
        // Exercise the same ownership/property checks with the test process's
        // UID so a non-root host runner can validate its own fixture files.
        DmaReservation::observe_tree(root, unsafe { libc::geteuid() })
    }

    fn fixture() -> FixtureDirectory {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let serial = NEXT.fetch_add(1, Ordering::SeqCst);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "bm1391-dma-fixture-{}-{stamp}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = FixtureDirectory(path);
        std::fs::create_dir_all(directory.path().join(NODE)).unwrap();
        std::fs::create_dir(directory.path().join("memory@0")).unwrap();
        for (name, bytes) in [
            ("#address-cells", vec![0, 0, 0, 1]),
            ("#size-cells", vec![0, 0, 0, 1]),
            ("reserved-memory/#address-cells", vec![0, 0, 0, 1]),
            ("reserved-memory/#size-cells", vec![0, 0, 0, 1]),
            ("reserved-memory/ranges", vec![]),
            ("memory@0/reg", vec![0, 0, 0, 0, 0x10, 0, 0, 0]),
            (
                "reserved-memory/bm1391-dma@f000000/reg",
                vec![0x0f, 0, 0, 0, 1, 0, 0, 0],
            ),
            ("reserved-memory/bm1391-dma@f000000/no-map", vec![]),
            (
                "reserved-memory/bm1391-dma@f000000/compatible",
                b"dcent,bm1391-stock-fpga-dma\0".to_vec(),
            ),
        ] {
            let path = directory.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        directory
    }

    #[test]
    fn exact_kernel_reservation_is_required_before_native_mapping() {
        let directory = fixture();
        let region = observe(directory.path()).unwrap();
        assert_eq!(
            (region.physical_base(), region.bytes()),
            (0x0f000000, 0x01000000)
        );
        for (name, bytes) in [
            ("reg", vec![0x3f, 0, 0, 0, 1, 0, 0, 0]),
            ("no-map", vec![1]),
            ("compatible", b"another-fabric\0".to_vec()),
        ] {
            let directory = fixture();
            let path = directory.path().join(NODE).join(name);
            std::fs::write(&path, bytes).unwrap();
            assert!(observe(directory.path()).is_err());
        }
        for flag in ["reusable", "status"] {
            let directory = fixture();
            std::fs::write(directory.path().join(NODE).join(flag), b"").unwrap();
            assert!(observe(directory.path()).is_err());
        }
        let path = directory.path().join(NODE).join("reg");
        let saved = directory.path().join("saved");
        std::fs::rename(&path, &saved).unwrap();
        symlink(saved, path).unwrap();
        assert!(observe(directory.path()).is_err());
    }
}
