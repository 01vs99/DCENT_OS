// SPDX-License-Identifier: GPL-3.0-or-later
//! R05 scripted I²C wire for the S17 PIC dialects.
//!
//! Implements the fake-transport recommendation 2 of
//!
//! (§3.2 "Shared fault-scheduled I²C wire harness … shaped like `S17PicWire`
//! … with the NACK-flush rule modeled"), including that report's EXACT fault
//! interface `Nack { after_writes: u32 }`: a fault fires on the first
//! transaction AFTER `after_writes` successful transactions, not before.
//! Tests-only: never compiled into the daemon binary.
//!
//! The flush rule is load-bearing (rust-firmware rule #25): after ANY I²C
//! NACK the caller must flush 16 zero bytes to the PIC or its MSSP parser
//! stays corrupted until power cycle. The production owner of that rule is
//! `NativeHardware::pic` (`s17_native_runtime.rs`), which issues the
//! 16-zero write through the same serialized bus owner on every error. This
//! harness lets a test play the caller and ACCOUNT for the flush.

use super::s17_wire::S17PicWire;

/// Schedulable wire faults (f04 report §3.2). `after_writes` counts
/// SUCCESSFUL transactions that must complete before the fault may fire;
/// `after_writes: 0` faults the very first transaction.
#[derive(Debug, Clone)]
pub enum I2cFault {
    /// Write phase is NACKed (the parser-corruption path; a 16-zero flush
    /// must follow before the PIC parses again).
    Nack { after_writes: u32 },
    /// No reply at all (transaction times out at the caller).
    SilentTimeout { after_writes: u32 },
    /// The scripted reply is emitted with every byte XORed — a corrupt or
    /// bit-flipped reply that must fail the checksum/opcode correlation.
    ReplyCorrupt { xor: u8, after_writes: u32 },
}

impl I2cFault {
    fn eligible(&self, ok_writes: u32) -> bool {
        match *self {
            I2cFault::Nack { after_writes }
            | I2cFault::SilentTimeout { after_writes }
            | I2cFault::ReplyCorrupt { after_writes, .. } => ok_writes >= after_writes,
        }
    }
}

/// Scripted replies keyed by exact (address, write-bytes) plus scheduled
/// fault injection, with NACK/flush accounting.
#[derive(Default)]
pub struct ScriptedS17I2cWire {
    /// Every attempted transaction write: `(addr, bytes)` in order.
    pub log: Vec<(u8, Vec<u8>)>,
    /// Every 16-zero flush write issued through [`ScriptedS17I2cWire::flush_after_nack`].
    pub flush_log: Vec<(u8, Vec<u8>)>,
    expects: Vec<(u8, Vec<u8>, std::io::Result<Vec<u8>>)>,
    injected: Vec<I2cFault>,
    /// Successful (non-error) transaction count, for `after_writes`.
    ok_writes: u32,
    pub nack_events: u32,
    pub flush_events: u32,
}

impl ScriptedS17I2cWire {
    pub fn new() -> Self {
        Self::default()
    }

    /// Script one reply for an exact `(addr, write)` transaction.
    pub fn expect(&mut self, addr: u8, write: &[u8], reply: Vec<u8>) -> &mut Self {
        self.expects.push((addr, write.to_vec(), Ok(reply)));
        self
    }

    /// Script an error reply for an exact `(addr, write)` transaction.
    pub fn expect_err(&mut self, addr: u8, write: &[u8], kind: std::io::ErrorKind) -> &mut Self {
        self.expects.push((
            addr,
            write.to_vec(),
            Err(std::io::Error::new(kind, "scripted error")),
        ));
        self
    }

    /// Schedule one-shot faults, consumed in order once each becomes
    /// eligible (see [`I2cFault`]).
    pub fn inject(&mut self, fault: I2cFault) -> &mut Self {
        self.injected.push(fault);
        self
    }

    /// The production recovery contract (rule #25): after a NACK the same
    /// serialized bus owner writes 16 zero bytes to the PIC. Tests call this
    /// exactly where `NativeHardware::pic` does — on the error path.
    pub fn flush_after_nack(&mut self, addr: u8) {
        self.flush_log.push((addr, vec![0u8; 16]));
        self.flush_events += 1;
    }

    /// Number of logged transactions (excluding flushes).
    pub fn transaction_count(&self) -> usize {
        self.log.len()
    }

    fn take_matching_expect(
        &mut self,
        i2c_addr: u8,
        write: &[u8],
    ) -> Option<std::io::Result<Vec<u8>>> {
        let position = self
            .expects
            .iter()
            .position(|(addr, wr, _)| *addr == i2c_addr && wr.as_slice() == write)?;
        let (_, _, reply) = self.expects.remove(position);
        Some(reply)
    }
}

impl S17PicWire for ScriptedS17I2cWire {
    fn transact(
        &mut self,
        i2c_addr: u8,
        write: &[u8],
        _read_len: usize,
    ) -> std::io::Result<Vec<u8>> {
        self.log.push((i2c_addr, write.to_vec()));
        // Consume the first ELIGIBLE fault (after_writes satisfied).
        let position = self
            .injected
            .iter()
            .position(|fault| fault.eligible(self.ok_writes));
        if let Some(position) = position {
            match self.injected.remove(position) {
                I2cFault::Nack { .. } => {
                    self.nack_events += 1;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "scripted NACK on write phase",
                    ));
                }
                I2cFault::SilentTimeout { .. } => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "scripted silence",
                    ));
                }
                I2cFault::ReplyCorrupt { xor, .. } => {
                    let reply = self
                        .take_matching_expect(i2c_addr, write)
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "no scripted reply for corrupt transaction",
                            )
                        })?;
                    let reply = reply.map(|bytes| bytes.iter().map(|b| b ^ xor).collect());
                    if reply.is_ok() {
                        self.ok_writes += 1;
                    }
                    return reply;
                }
            }
        }
        let reply = self
            .take_matching_expect(i2c_addr, write)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "no scripted reply"))?;
        if reply.is_ok() {
            self.ok_writes += 1;
        }
        reply
    }
}

/// Build a framed reply with the dialect checksum law: `[LEN CMD payload…
/// SUM16-BE]` where `LEN` is the total byte count. The PIC replies use the
/// same law as the commands (jig `get_PIC16F1704_software_version@2302C`).
pub fn framed_reply_bytes(cmd: u8, payload: &[u8]) -> Vec<u8> {
    let len = (payload.len() + 4) as u8;
    let mut frame = Vec::with_capacity(payload.len() + 6);
    let sum = u16::from(len)
        + u16::from(cmd)
        + payload.iter().map(|&b| u16::from(b)).sum::<u16>();
    frame.push(len);
    frame.push(cmd);
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&sum.to_be_bytes());
    frame
}
