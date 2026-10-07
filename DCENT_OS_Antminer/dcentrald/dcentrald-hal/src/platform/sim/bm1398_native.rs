// Opt-in BM1398 raw command FIFO fixture for the existing SimChain state.
// Independent population is supplied before any command, never inferred from
// the number of addresses sent by the production initializer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimBm1398WireFault {
    None,
    MissingLastChip,
    BadResponseCrc,
}
#[derive(Debug)]
struct SimBm1398Wire {
    chips: u8,
    interval: u8,
    assigned: Vec<u8>,
    pending_write: Option<(Option<u8>, u8)>,
    fault: SimBm1398WireFault,
}
impl SimChain {
    pub fn configure_bm1398_native_wire(
        &self,
        chips: u8,
        interval: u8,
        fault: SimBm1398WireFault,
    ) -> Result<()> {
        let mut state = self.lock()?;
        if state.profile.chip_id != 0x1398
            || !state.trace.is_empty()
            || state.bm1398_native.is_some()
            || !matches!((chips, interval), (114, 2) | (76, 3) | (72, 3) | (80, 3))
        {
            return Err(HalError::Other(
                "BM1398 wire fixture requires an untouched exact population".into(),
            ));
        }
        state.bm1398_native = Some(SimBm1398Wire {
            chips,
            interval,
            assigned: vec![],
            pending_write: None,
            fault,
        });
        state.registers.insert((u8::MAX, 0x18), 0x0000_7a31);
        Ok(())
    }
}
impl SimBm1398Wire {
    fn response_crc(bytes: &[u8]) -> u8 {
        // Bit-matrix form of the BM13xx response recurrence. Independent of
        // the production parser; pinned below by the captured zero-chip body.
        bytes.iter().fold(3, |mut crc, byte| {
            for bit in (0..8).rev() {
                let carry = crc >> 4;
                crc = ((crc << 1) & 31) ^ (carry * 5) ^ (((byte >> bit) & 1) * 13);
            }
            crc
        })
    }
    fn response(&self, responses: &mut VecDeque<Vec<u8>>, value: u32, address: u8, register: u8) {
        let mut payload = value.to_be_bytes().to_vec();
        payload.extend([address, register]);
        let crc = Self::response_crc(&payload)
            ^ u8::from(self.fault == SimBm1398WireFault::BadResponseCrc);
        responses.push_back(value.to_be_bytes().to_vec());
        // Actual CommandBackend reads the first THREE metadata bytes. BM1398
        // CRC is byte6 of the seven-byte body, not the unrelated fourth byte.
        responses.push_back(vec![address, register, crc, 0]);
    }
    fn command(
        &mut self,
        bytes: &[u8],
        registers: &mut HashMap<(u8, u8), u32>,
        responses: &mut VecDeque<Vec<u8>>,
    ) -> Result<()> {
        if bytes.len() != 4 {
            return Err(HalError::Other("BM1398 raw FIFO word width".into()));
        }
        if let Some((address, register)) = self.pending_write.take() {
            registers.insert(
                (address.unwrap_or(u8::MAX), register),
                u32::from_be_bytes(bytes.try_into().unwrap()),
            );
            return Ok(());
        }
        match (bytes[0], bytes[1]) {
            (0x51, 9) => self.pending_write = Some((None, bytes[3])),
            (0x41, 9) => self.pending_write = Some((Some(bytes[2]), bytes[3])),
            (0x53, 5) => self.assigned.clear(),
            (0x40, 5) => {
                if self.assigned.len() >= usize::from(self.chips)
                    || bytes[2] != self.assigned.len() as u8 * self.interval
                {
                    return Err(HalError::Other(
                        "BM1398 fixture assignment is not the observed stock geometry".into(),
                    ));
                }
                self.assigned.push(bytes[2]);
            }
            (0x52, 5) if bytes[2..] == [0, 0] => {
                let count =
                    self.chips - u8::from(self.fault == SimBm1398WireFault::MissingLastChip);
                for index in 0..count {
                    // Unassigned physical chips report zero; copying the
                    // requested count would hide a missing/duplicate census.
                    let address = self.assigned.get(usize::from(index)).copied().unwrap_or(0);
                    self.response(responses, 0x1398_1800 | u32::from(address), 0, 0);
                }
            }
            (0x42, 5) => {
                let address = bytes[2];
                let register = bytes[3];
                let value = registers
                    .get(&(address, register))
                    .or_else(|| registers.get(&(u8::MAX, register)))
                    .copied()
                    .unwrap_or(0);
                self.response(responses, value, address, register);
            }
            _ => return Err(HalError::Other("unowned BM1398 command FIFO word".into())),
        }
        Ok(())
    }
}
#[cfg(test)]
mod bm1398_wire_tests {
    use super::*;
    #[test]
    fn captured_seven_byte_body_and_correlated_register_metadata_are_preserved() {
        assert_eq!(SimBm1398Wire::response_crc(&[0x13, 0x98, 0x18, 0, 0, 0]), 4);
        let mut model = SimBm1398Wire {
            chips: 114,
            interval: 2,
            assigned: vec![],
            pending_write: None,
            fault: SimBm1398WireFault::None,
        };
        let mut registers = HashMap::new();
        let mut replies = VecDeque::new();
        for index in 0..114 {
            model
                .command(&[0x40, 5, index * 2, 0], &mut registers, &mut replies)
                .unwrap();
        }
        model
            .command(&[0x52, 5, 0, 0], &mut registers, &mut replies)
            .unwrap();
        assert_eq!(replies.len(), 228);
        assert_eq!(replies.pop_front().unwrap(), [0x13, 0x98, 0x18, 0]);
        assert_eq!(replies.pop_front().unwrap(), [0, 0, 4, 0]);
        replies.clear();
        model
            .command(&[0x51, 9, 0, 0x18], &mut registers, &mut replies)
            .unwrap();
        model
            .command(&[0, 0, 0x61, 0x31], &mut registers, &mut replies)
            .unwrap();
        model
            .command(&[0x42, 5, 0, 0x18], &mut registers, &mut replies)
            .unwrap();
        assert_eq!(replies.pop_front().unwrap(), [0, 0, 0x61, 0x31]);
        let metadata = replies.pop_front().unwrap();
        assert_eq!(&metadata[..2], &[0, 0x18]);
        assert_eq!(metadata, [0, 0x18, 4, 0]); // independent bit-transition calculation
    }
}
