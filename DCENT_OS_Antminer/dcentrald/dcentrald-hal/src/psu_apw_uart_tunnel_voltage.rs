//! APW hardware0x76 numerical wire codec from the held BB LuxOS binary.
//!
//! ELF0x5aa3b0 selects the coefficients at0x5aa848/0x5aa850 for hardware0x76.
//! ELF0x5a6f08 reads opcode03 and truncates the inverse to centivolts. The
//! retained269 original-function executions include every one-byte read code.
//! This codec neither selects a safe operating voltage nor controls a rail.

use crate::{HalError, Result};

const OFFSET: f64 = 1190.93534;
const SLOPE: f64 = 78.742588;

/// One-byte DAC value for the exact APW hardware0x76 conversion table.
/// Other hardware tables can use wider payloads and different coefficients.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Apw76VoltageCode(u8);

impl Apw76VoltageCode {
    /// Encode only the numerical one-byte domain without donor saturation.
    /// The controller must separately qualify the board, PSU and operating
    /// limits before using this value in an electrical command.
    pub fn from_millivolts(millivolts: u16) -> Result<Self> {
        let code = OFFSET - (f64::from(millivolts) / 1000.0) * SLOPE;
        if !(0.0..256.0).contains(&code) {
            return Err(HalError::PsuUnsupported(format!(
                "APW hardware0x76 voltage{millivolts}mV is outside the one-byte numerical domain"
            )));
        }
        Ok(Self(code as u8))
    }

    /// Decode an exact two-byte response field. A nonzero high byte belongs
    /// to an unqualified numerical domain, even when its checksum is valid.
    pub fn from_reply(data: &[u8]) -> Result<Self> {
        match data {
            [code, 0] => Ok(Self(*code)),
            _ => Err(HalError::PsuProtocolOwned(
                "APW hardware0x76 voltage response requires exactly one DAC byte and zero high byte"
                    .into(),
            )),
        }
    }

    pub fn payload(self) -> [u8; 2] {
        [self.0, 0]
    }

    /// Original readback conversion truncates to hundredths of a volt.
    /// This is decoded PSU-reported data, not a measured hashboard rail.
    pub fn reported_millivolts(self) -> u16 {
        let centivolts = ((OFFSET - f64::from(self.0)) / SLOPE * 100.0) as u16;
        centivolts * 10
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_original_read_code_and_retained_set_frame_match() {
        let evidence: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../"
        ))
        .unwrap();
        assert_eq!(evidence["complete_original_calls"], 269);
        let reads = evidence["read_vectors"].as_array().unwrap();
        assert_eq!(reads.len(), 256);
        for (code, original) in reads.iter().enumerate() {
            assert_eq!(original["read_dac_override"], code);
            let native = Apw76VoltageCode::from_reply(&[code as u8, 0]).unwrap();
            let expected =
                (original["decoded_voltage_v"][0].as_f64().unwrap() * 1000.0).round() as u16;
            assert_eq!(native.reported_millivolts(), expected, "code{code}");
        }
        for original in evidence["vectors"].as_array().unwrap() {
            let mv = (original["voltage_v"].as_f64().unwrap() * 1000.0).round() as u16;
            let code = Apw76VoltageCode::from_millivolts(mv).unwrap();
            let frame = crate::psu_apw_uart_tunnel::build_request(0x83, &code.payload()).unwrap();
            let hex = frame
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(hex, original["writes"][0]["frame"].as_str().unwrap());
        }
        assert_eq!(
            Apw76VoltageCode::from_reply(&[0x23, 0])
                .unwrap()
                .reported_millivolts(),
            14670
        );
    }

    #[test]
    fn no_saturation_truncated_field_or_foreign_high_word() {
        for mv in [0, 1000, 11000, 16000, u16::MAX] {
            assert!(Apw76VoltageCode::from_millivolts(mv).is_err());
        }
        for bytes in [&[][..], &[0x23][..], &[0x23, 1][..], &[0x23, 0, 0][..]] {
            assert!(Apw76VoltageCode::from_reply(bytes).is_err());
        }
    }
}
