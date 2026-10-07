//! Immutable packaging identity retained in the daemon's read-only ELF section.
//!
//! Layout v1 (196 bytes): profile[32] NUL-padded; layout u8; flags u8;
//! version length u8; reserved zero u8; Ed25519 public key[32];
//! version[128] NUL-padded. Flags: 1=common lab capability (including dependency
//! sim/recovery union), 2=daemon sim-hal, 4=reserved recovery, 8=missing OTA key,
//! 16=invalid OTA key/version. Packaging requires flags == 0.

const PROFILE: &[u8] = b"dcentos-build-identity/v1";
const VERSION: &[u8] = env!("CARGO_PKG_VERSION").as_bytes();

const fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

const fn identity() -> [u8; 196] {
    let mut bytes = [0u8; 196];
    let mut index = 0;
    while index < PROFILE.len() {
        bytes[index] = PROFILE[index];
        index += 1;
    }
    bytes[32] = 1;
    if dcentrald_common::lab_env::compiled() {
        bytes[33] |= 1;
    }
    if cfg!(feature = "sim-hal") {
        bytes[33] |= 2;
    }
    if VERSION.is_empty() || VERSION.len() > 128 {
        bytes[33] |= 16;
    } else {
        bytes[34] = VERSION.len() as u8;
        index = 0;
        while index < VERSION.len() {
            if VERSION[index] < 0x21 || VERSION[index] > 0x7e {
                bytes[33] |= 16;
            }
            bytes[68 + index] = VERSION[index];
            index += 1;
        }
    }
    match option_env!("DCENT_OTA_PUBLIC_KEY_HEX") {
        None => bytes[33] |= 8,
        Some(key) => {
            let key = key.as_bytes();
            if key.len() != 64 {
                bytes[33] |= 16;
            } else {
                index = 0;
                while index < 32 {
                    match (nibble(key[index * 2]), nibble(key[index * 2 + 1])) {
                        (Some(high), Some(low)) => bytes[36 + index] = (high << 4) | low,
                        _ => bytes[33] |= 16,
                    }
                    index += 1;
                }
            }
        }
    }
    bytes
}

#[used]
#[link_section = ".dcent.runtime"]
static BUILD_IDENTITY: [u8; 196] = identity();

/// Called by main so LTO and section garbage collection retain the inline data.
pub fn retain() {
    std::hint::black_box(&BUILD_IDENTITY);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_build_identity_matches_compiled_inputs() {
        retain();
        assert_eq!(&BUILD_IDENTITY[..PROFILE.len()], PROFILE);
        assert_eq!(BUILD_IDENTITY[32], 1);
        assert_eq!(
            BUILD_IDENTITY[33] & 1 != 0,
            dcentrald_common::lab_env::compiled()
        );
        assert_eq!(BUILD_IDENTITY[33] & 2 != 0, cfg!(feature = "sim-hal"));
        assert_eq!(
            BUILD_IDENTITY[33] & 8 != 0,
            option_env!("DCENT_OTA_PUBLIC_KEY_HEX").is_none()
        );
        assert_eq!(
            &BUILD_IDENTITY[68..68 + BUILD_IDENTITY[34] as usize],
            VERSION
        );
    }
}
