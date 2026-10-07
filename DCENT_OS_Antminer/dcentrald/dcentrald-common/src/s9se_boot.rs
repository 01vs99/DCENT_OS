//! S9 SE `BOOT.bin` and its actual FPGA configuration partition.
//!
//! The donor stores configuration words little-endian. The old BE-only sync
//! scan incorrectly concluded that no bitstream was present. Partition 1 is
//! a 2,083,744-byte PL payload with IDCODE 0x03723093 and 520,352 FDRI words.
//! Exact source: campaign evidence/r03/stock-source-manifest.json. Extracting
//! donor bytes is distinct from proving which fabric a running board loaded.

/// Inner `BOOT.bin` size.
pub const BOOT_BIN_SIZE: usize = 2_752_048;
pub const BOOT_BIN_SHA256: &str =
    "e7353cb4a4b06434f3fc36b203fb0c794c54dc70491d319c23b0df3bfdaab222";
/// Image identification at byte `0x24` (`XNLX`).
pub const BOOT_IMAGE_IDENT: [u8; 4] = *b"XNLX";
pub const BOOT_IMAGE_IDENT_OFF: usize = 0x24;
/// Word at `0x20` is the Zynq header copy of `0xAA995566` stored LE.
pub const BOOT_HEADER_SYNC_OFF: usize = 0x20;
pub const BOOT_HEADER_SYNC_LE: u32 = 0xAA99_5566;
/// U-Boot FPGA-part table includes `7z007s` among other Zynq SKUs.
pub const BOOT_STRING_7Z007S: &str = "7z007s";
/// FSBL names a bitstream download path. That is not a register map.
pub const BOOT_FSBL_BITSTREAM_NEEDLE: &str = "PCAP Bitstream Download Failed";
pub const FPGA_PARTITION_OFFSET: usize = 0x1d740;
pub const FPGA_PARTITION_BYTES: usize = 2_083_744;
pub const FPGA_PARTITION_SHA256: &str =
    "1681558e124de9a3721bf4fe4b885ba9a122d2a9f2a4d7e0f560824d95cdd6cc";
pub const FPGA_CONFIGURATION_IDCODE: u32 = 0x0372_3093;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeBootError {
    WrongSize { observed: usize },
    IdentMismatch,
    SyncMismatch,
    FabricAbiNotIdentified,
    InvalidPartition,
}

pub fn admit_boot_header(bytes: &[u8]) -> Result<(), S9SeBootError> {
    if bytes.len() != BOOT_BIN_SIZE {
        return Err(S9SeBootError::WrongSize {
            observed: bytes.len(),
        });
    }
    let ident = bytes
        .get(BOOT_IMAGE_IDENT_OFF..BOOT_IMAGE_IDENT_OFF + 4)
        .ok_or(S9SeBootError::IdentMismatch)?;
    if ident != BOOT_IMAGE_IDENT {
        return Err(S9SeBootError::IdentMismatch);
    }
    let sync = u32::from_le_bytes(
        bytes
            .get(BOOT_HEADER_SYNC_OFF..BOOT_HEADER_SYNC_OFF + 4)
            .ok_or(S9SeBootError::SyncMismatch)?
            .try_into()
            .map_err(|_| S9SeBootError::SyncMismatch)?,
    );
    if sync != BOOT_HEADER_SYNC_LE {
        return Err(S9SeBootError::SyncMismatch);
    }
    Ok(())
}

/// A sync-word boolean alone does not identify the loaded fabric ABI.
pub fn refuse_boot_bitstream_abi(has_raw_aa995566_payload: bool) -> Result<(), S9SeBootError> {
    let _ = has_raw_aa995566_payload;
    Err(S9SeBootError::FabricAbiNotIdentified)
}

/// Extract the exact PL partition, checking its header checksum and actual
/// Xilinx packet structure. A consumer must bind the donor SHA and successful
/// boot programming before using the corresponding stock register transport.
pub fn fpga_configuration_partition(bytes: &[u8]) -> Result<&[u8], S9SeBootError> {
    admit_boot_header(bytes)?;
    let word = |offset: usize| -> Result<u32, S9SeBootError> {
        let raw = bytes
            .get(offset..offset + 4)
            .ok_or(S9SeBootError::InvalidPartition)?;
        Ok(u32::from_le_bytes(raw.try_into().unwrap()))
    };
    if word(0x9c)? != 0xc80 {
        return Err(S9SeBootError::InvalidPartition);
    }
    let header: Vec<u32> = (0..16)
        .map(|index| word(0xcc0 + index * 4))
        .collect::<Result<_, _>>()?;
    if header
        .iter()
        .fold(0u32, |sum, value| sum.wrapping_add(*value))
        != u32::MAX
        || header[0] != (FPGA_PARTITION_BYTES / 4) as u32
        || header[1] != header[0]
        || header[2] != header[0]
        || header[5] != (FPGA_PARTITION_OFFSET / 4) as u32
        || header[6] != 0x20
    {
        return Err(S9SeBootError::InvalidPartition);
    }
    let partition = &bytes[FPGA_PARTITION_OFFSET..FPGA_PARTITION_OFFSET + FPGA_PARTITION_BYTES];
    let mut offset = 0x30;
    if u32::from_le_bytes(partition[offset..offset + 4].try_into().unwrap()) != BOOT_HEADER_SYNC_LE
    {
        return Err(S9SeBootError::InvalidPartition);
    }
    offset += 4;
    let (mut register, mut idcode, mut fdri, mut desync) = (0, None, false, false);
    while offset + 4 <= partition.len() {
        let packet = u32::from_le_bytes(partition[offset..offset + 4].try_into().unwrap());
        let kind = packet >> 29;
        if kind != 1 && kind != 2 {
            break;
        }
        let count = (packet & if kind == 1 { 0x7ff } else { 0x7ff_ffff }) as usize;
        if kind == 1 {
            register = (packet >> 13) & 31;
        }
        let end = offset
            .checked_add((count + 1) * 4)
            .ok_or(S9SeBootError::InvalidPartition)?;
        if end > partition.len() {
            return Err(S9SeBootError::InvalidPartition);
        }
        if (packet >> 27) & 3 == 2 && count > 0 {
            let value = u32::from_le_bytes(partition[offset + 4..offset + 8].try_into().unwrap());
            if register == 12 && count == 1 {
                idcode = Some(value);
            }
            if register == 2 && count == 520_352 {
                fdri = true;
            }
            if register == 4 && count == 1 && value == 13 {
                desync = true;
            }
        }
        offset = end;
    }
    if idcode != Some(FPGA_CONFIGURATION_IDCODE) || !fdri || !desync {
        return Err(S9SeBootError::InvalidPartition);
    }
    Ok(partition)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_constants_match_held_image_metadata() {
        assert_eq!(BOOT_BIN_SIZE, 2_752_048);
        assert_eq!(BOOT_BIN_SHA256.len(), 64);
        assert_eq!(BOOT_IMAGE_IDENT, *b"XNLX");
        assert_eq!(BOOT_HEADER_SYNC_LE, 0xAA99_5566);
        assert!(BOOT_STRING_7Z007S.contains("7z007"));
        assert_eq!(
            refuse_boot_bitstream_abi(false),
            Err(S9SeBootError::FabricAbiNotIdentified)
        );
        assert_eq!(
            refuse_boot_bitstream_abi(true),
            Err(S9SeBootError::FabricAbiNotIdentified)
        );
    }

    #[test]
    fn admit_boot_header_checks_size_ident_and_sync() {
        let mut fake = vec![0u8; BOOT_BIN_SIZE];
        fake[BOOT_HEADER_SYNC_OFF..BOOT_HEADER_SYNC_OFF + 4]
            .copy_from_slice(&BOOT_HEADER_SYNC_LE.to_le_bytes());
        fake[BOOT_IMAGE_IDENT_OFF..BOOT_IMAGE_IDENT_OFF + 4].copy_from_slice(&BOOT_IMAGE_IDENT);
        admit_boot_header(&fake).unwrap();
        assert!(admit_boot_header(&fake[..10]).is_err());
        fake[BOOT_IMAGE_IDENT_OFF] = b'Z';
        assert_eq!(admit_boot_header(&fake), Err(S9SeBootError::IdentMismatch));
    }

    #[test]
    fn admit_boot_header_accepts_held_s9se_image() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../");
        let bytes = std::fs::read(&path).expect("held S9 SE BOOT.bin");
        assert_eq!(bytes.len(), BOOT_BIN_SIZE);
        admit_boot_header(&bytes).unwrap();
        let partition = fpga_configuration_partition(&bytes).unwrap();
        assert_eq!(partition.len(), FPGA_PARTITION_BYTES);
        assert_eq!(&partition[0x30..0x34], &[0x66, 0x55, 0x99, 0xaa]);
        assert!(bytes
            .windows(BOOT_STRING_7Z007S.len())
            .any(|w| w == BOOT_STRING_7Z007S.as_bytes()));
    }

    #[test]
    fn held_s9se_partition_rejects_header_and_configuration_corruption() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../");
        let bytes = std::fs::read(path).unwrap();
        for offset in [0xcc0, 0xcc0 + 20, 0x1d770, 0x1d7c0, 0x1d828] {
            let mut corrupt = bytes.clone();
            corrupt[offset] ^= 1;
            assert!(
                fpga_configuration_partition(&corrupt).is_err(),
                "offset {offset:#x}"
            );
        }
    }
}
