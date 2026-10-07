//! Four authored pure diagnostic groups; detached and uncompiled.
use super::*;

fn reply(opcode: u8, data: &[u8], total: usize) -> Vec<Vec<u8>> {
    let length = 4 + data.len() as u8;
    let checksum = data.iter().map(|byte| u16::from(*byte)).sum::<u16>()
        + u16::from(length)
        + u16::from(opcode);
    let mut bytes = vec![0x55, 0xaa, length, opcode];
    bytes.extend_from_slice(data);
    bytes.extend_from_slice(&checksum.to_le_bytes());
    bytes.resize(total, 0xf5);
    vec![bytes]
}

#[test]
fn four_fixed_requests_keep_existing_native_delay_and_read_shape() {
    let expected = [
        (Query::Hardware, vec![0x11, 0x55, 0xaa, 4, 2, 6, 0], 500, 8),
        (Query::Firmware, vec![0x11, 0x55, 0xaa, 4, 1, 5, 0], 500, 8),
        (
            Query::Calibration,
            vec![0x11, 0x55, 0xaa, 6, 6, 0x40, 0x20, 0x6c, 0],
            1200,
            40,
        ),
        (Query::Dac, vec![0x11, 0x55, 0xaa, 4, 3, 7, 0], 500, 10),
    ];
    for (query, request, delay, read_len) in expected {
        let steps = query.steps().unwrap();
        let [I2cTransactionStep::Write(bytes), I2cTransactionStep::SleepMs(ms), I2cTransactionStep::Read(size)] =
            steps.as_slice()
        else {
            panic!("exact compound request/delay/reply required")
        };
        assert_eq!(bytes, &request);
        assert_eq!((*ms, *size), (delay, read_len));
        assert!(![0x81, 0x83].contains(&bytes[4]));
    }
}

#[test]
fn exact_identity_and_calibration_address_length_checksum_are_required() {
    for value in 0..=u8::MAX {
        assert_eq!(
            Query::Hardware.decode(&reply(2, &[value, 0], 8)).is_ok(),
            value == 0x76
        );
        assert_eq!(
            Query::Firmware.decode(&reply(1, &[value, 0], 8)).is_ok(),
            value == 0x17
        );
        if value != 0 {
            assert!(Query::Hardware
                .decode(&reply(2, &[0x76, value], 8))
                .is_err());
            assert!(Query::Firmware
                .decode(&reply(1, &[0x17, value], 8))
                .is_err());
        }
    }
    let mut data = vec![0x40];
    data.extend([0xff; 32]);
    let raw = reply(6, &data, 40);
    assert_eq!(&raw[0][37..], &[0x4b, 0x20, 0xf5]);
    assert_eq!(
        Query::Calibration.decode(&raw).unwrap(),
        Field::Calibration([0xff; 32])
    );
    for address in 0..=u8::MAX {
        data[0] = address;
        assert_eq!(
            Query::Calibration.decode(&reply(6, &data, 40)).is_ok(),
            address == 0x40
        );
    }
    data[0] = 0x40;
    for length in 0..33 {
        assert!(Query::Calibration
            .decode(&reply(6, &data[..length], 40))
            .is_err());
    }
    let mut bad = raw.clone();
    bad[0][38] ^= 1;
    assert!(Query::Calibration.decode(&bad).is_err());
}

#[test]
fn all_raw_dac_words_survive_even_outside_one_byte_voltage_conversion() {
    for raw in 0..=u16::MAX {
        let Field::Dac {
            raw: actual,
            millivolts,
        } = Query::Dac
            .decode(&reply(3, &raw.to_le_bytes(), 10))
            .unwrap()
        else {
            panic!("DAC field required")
        };
        assert_eq!(actual, raw);
        assert_eq!(millivolts.is_some(), raw <= 255);
    }
    assert_eq!(
        Query::Dac.decode(&reply(3, &[0, 0], 10)).unwrap(),
        Field::Dac {
            raw: 0,
            millivolts: Some(15120)
        }
    );
    assert_eq!(
        Query::Dac.decode(&reply(3, &[0x23, 0], 10)).unwrap(),
        Field::Dac {
            raw: 0x23,
            millivolts: Some(14670)
        }
    );
    for data in [vec![], vec![0], vec![0, 0, 0], vec![0, 0, 0, 0]] {
        assert!(Query::Dac.decode(&reply(3, &data, 10)).is_err());
    }
}

#[test]
fn response_record_boundaries_padding_and_echo_cannot_be_normalized_away() {
    let good = reply(2, &[0x76, 0], 8);
    for length in 0..=16 {
        let mut raw = good.clone();
        raw[0].resize(length, 0xf5);
        assert_eq!(Query::Hardware.decode(&raw).is_ok(), length == 8);
    }
    assert!(Query::Hardware.decode(&[]).is_err());
    assert!(Query::Hardware
        .decode(&[good[0][..4].to_vec(), good[0][4..].to_vec()])
        .is_err());
    assert!(Query::Hardware.decode(&[good[0].clone(), vec![]]).is_err());
    assert!(Query::Hardware.decode(&reply(1, &[0x76, 0], 8)).is_err());
    for index in [0, 1, 2, 6, 7] {
        let mut raw = good.clone();
        raw[0][index] ^= 1;
        assert!(Query::Hardware.decode(&raw).is_err());
    }
    let mut padded = reply(3, &[0x23, 0], 10);
    assert!(Query::Dac.decode(&padded).is_ok());
    padded[0][9] = 0;
    assert!(Query::Dac.decode(&padded).is_err());
}
