//! Transport-neutral ASIC protocol pure policy (ADR-0010 / decade P1-3 seed).
//!
//! # Why
//!
//! `ChipDriver` historically took `&mut FpgaChain` and mixed protocol framing with
//! Zynq I/O. Production paths also speak serial (AM2/AML/BB) and must not inherit
//! FPGA-only method signatures. Voltage is already a separate [`crate::voltage_rail`]
//! facet. This module is the **pure composition gate** for:
//!
//! - which [`AsicProtocolIdentity`] may mutate over which [`ChainTransportKind`]
//! - which pure mutation capabilities a protocol admits (without I/O)
//! - a declarative [`InitProgram`] / [`InitStep`] shape for future stranglers
//!
//! # Status
//!
//! **PRODUCTION pure policy** for admission and capability masks. Engine I/O
//! adapters (`ChainTransport` trait over Fpga/Serial/UartTrans) remain a
//! multi-cycle strangler residual — this module does not open hardware.

use crate::board_desc::{AsicProtocolIdentity, BoardDesc, ChainTransportKind, WorkEngineKind};

/// Why a protocol×transport pair was refused for mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolTransportError {
    /// Board is management-only / no chain open.
    ManagementOnlyTransport,
    /// Runtime must discover silicon before protocol mutation.
    RuntimeDiscoveredProtocol,
    /// Declared protocol and transport combination is not in the evidence matrix.
    Incompatible {
        protocol: AsicProtocolIdentity,
        transport: ChainTransportKind,
    },
    /// Work engine facet cannot push hash work on this transport.
    WorkEngineIncompatible {
        transport: ChainTransportKind,
        work_engine: WorkEngineKind,
    },
}

impl std::fmt::Display for ProtocolTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ManagementOnlyTransport => {
                write!(
                    f,
                    "chain transport is None — management-only, no ASIC mutation"
                )
            }
            Self::RuntimeDiscoveredProtocol => write!(
                f,
                "ASIC protocol is RuntimeDiscovered — refuse mutation until measured identity"
            ),
            Self::Incompatible {
                protocol,
                transport,
            } => write!(
                f,
                "ASIC protocol {protocol:?} is not admitted over transport {transport:?}"
            ),
            Self::WorkEngineIncompatible {
                transport,
                work_engine,
            } => write!(
                f,
                "work engine {work_engine:?} is not admitted over transport {transport:?}"
            ),
        }
    }
}

impl std::error::Error for ProtocolTransportError {}

/// Proof that a protocol identity may speak mutation frames over a transport.
///
/// Private field so engines cannot mint the proof from literals — only
/// [`admit_protocol_over_transport`] and [`BoardDesc::admit_protocol_transport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolTransportAdmission {
    protocol: AsicProtocolIdentity,
    transport: ChainTransportKind,
}

impl ProtocolTransportAdmission {
    pub const fn protocol(self) -> AsicProtocolIdentity {
        self.protocol
    }

    pub const fn transport(self) -> ChainTransportKind {
        self.transport
    }
}

/// Pure mutation capabilities a protocol identity can prepare without I/O.
///
/// Engines use this to refuse UI/API claims that a chip can do PLL/work when
/// the pure model has no table — not as a live bench proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolCapabilities {
    pub get_address_enumerate: bool,
    pub assign_chip_addresses: bool,
    pub work_submit: bool,
    /// Frequency / PLL program preparation (tables live in silicon-profiles).
    pub frequency_program: bool,
    /// Version-rolling / midstate work codecs (family-specific).
    pub version_rolling_work: bool,
}

/// Declarative init step — pure data, no I/O.
///
/// Adapters sleep/GPIO/UART/FPGA; this only describes ordered intent so
/// hybrid/serial/stock cannot fork incompatible bring-up narratives forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitStep {
    /// Software-visible delay before the next mutation.
    DelayMs(u32),
    /// Soft-reset / chain reset intent (transport-specific encoding later).
    SoftReset,
    /// Enumerate / GET_ADDRESS at a named baud stage (label is forensic only).
    EnumerateAtBaud { baud_label: &'static str },
    /// Assign consecutive chip addresses after a known chip count.
    AssignAddresses { chip_count: u8 },
    /// Program frequency / PLL (value is pure intent; PLL tables elsewhere).
    ProgramFrequencyMhz { frequency_mhz: u16 },
}

/// Ordered pure init program for one chain.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InitProgram {
    pub steps: Vec<InitStep>,
}

impl InitProgram {
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    pub fn len(&self) -> usize {
        self.steps.len()
    }
}

/// Admit protocol mutation over a chain transport (evidence matrix from BoardDesc).
///
/// Derived from the in-tree BoardDesc registry + ADR-0010: FPGA UIO for S9-class
/// BM1387; Zynq hybrid / serial for BM1362 AM2; serial for Amlogic BM1366/68/70;
/// management `None` and `RuntimeDiscovered` always refuse.
pub fn admit_protocol_over_transport(
    protocol: AsicProtocolIdentity,
    transport: ChainTransportKind,
) -> Result<ProtocolTransportAdmission, ProtocolTransportError> {
    if matches!(transport, ChainTransportKind::None) {
        return Err(ProtocolTransportError::ManagementOnlyTransport);
    }
    if matches!(protocol, AsicProtocolIdentity::RuntimeDiscovered) {
        return Err(ProtocolTransportError::RuntimeDiscoveredProtocol);
    }

    let ok = match (protocol, transport) {
        // S9 / stock FPGA BM1387 class
        (
            AsicProtocolIdentity::Bm1387,
            ChainTransportKind::FpgaUio | ChainTransportKind::StockFpga,
        ) => true,
        // S15/T15 catalog identity — management transport only until serial layout
        // is admitted (BoardDesc uses None today); refuse active chain transports.
        (
            AsicProtocolIdentity::Bm1391
            | AsicProtocolIdentity::Bm1393
            | AsicProtocolIdentity::Bm1396,
            _,
        ) => false,
        // BM139x AM2 native / hybrid / serial / uart_trans family. The S17
        // native lifecycle owns StockFpga with its work/nonce FIFOs; the R07 S19
        // Pro lifecycle (am2-s19pro) additionally runs BM1398 over its
        // retained-owner FPGA UIO work FIFO, so that exact tuple admits.
        (
            AsicProtocolIdentity::Bm1397,
            ChainTransportKind::ZynqHybrid
                | ChainTransportKind::Serial
                | ChainTransportKind::UartTrans
                | ChainTransportKind::StockFpga,
        ) => true,
        (
            AsicProtocolIdentity::Bm1398,
            ChainTransportKind::ZynqHybrid
                | ChainTransportKind::Serial
                | ChainTransportKind::UartTrans
                | ChainTransportKind::FpgaUio,
        ) => true,
        // BM1362 — hybrid (XIL) + serial (BB) + uart_trans (CV evidence rows)
        (
            AsicProtocolIdentity::Bm1362,
            ChainTransportKind::ZynqHybrid
            | ChainTransportKind::Serial
            | ChainTransportKind::UartTrans,
        ) => true,
        // Amlogic / serial BM1366/68/70
        (
            AsicProtocolIdentity::Bm1366
            | AsicProtocolIdentity::Bm1368
            | AsicProtocolIdentity::Bm1370,
            ChainTransportKind::Serial | ChainTransportKind::UartTrans,
        ) => true,
        _ => false,
    };

    if ok {
        Ok(ProtocolTransportAdmission {
            protocol,
            transport,
        })
    } else {
        Err(ProtocolTransportError::Incompatible {
            protocol,
            transport,
        })
    }
}

/// Admit work-engine facet against transport (composition second check).
pub fn admit_work_engine_over_transport(
    transport: ChainTransportKind,
    work_engine: WorkEngineKind,
) -> Result<(), ProtocolTransportError> {
    let ok = match (transport, work_engine) {
        (ChainTransportKind::None, WorkEngineKind::ManagementOnly) => true,
        (ChainTransportKind::None, _) => false,
        (_, WorkEngineKind::ManagementOnly) => false,
        (ChainTransportKind::FpgaUio, WorkEngineKind::FpgaWorkFifo) => true,
        (ChainTransportKind::StockFpga, WorkEngineKind::StockDma | WorkEngineKind::FpgaWorkFifo) => true,
        (
            ChainTransportKind::Serial | ChainTransportKind::UartTrans,
            WorkEngineKind::SerialWork,
        ) => true,
        // Hybrid may use FPGA FIFO and/or serial work depending on recipe.
        (
            ChainTransportKind::ZynqHybrid,
            WorkEngineKind::FpgaWorkFifo | WorkEngineKind::SerialWork,
        ) => true,
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(ProtocolTransportError::WorkEngineIncompatible {
            transport,
            work_engine,
        })
    }
}

/// Pure capability mask for a protocol identity (no I/O, no PLL table claim).
pub fn protocol_capabilities(protocol: AsicProtocolIdentity) -> ProtocolCapabilities {
    match protocol {
        AsicProtocolIdentity::RuntimeDiscovered => ProtocolCapabilities {
            get_address_enumerate: false,
            assign_chip_addresses: false,
            work_submit: false,
            frequency_program: false,
            version_rolling_work: false,
        },
        // Catalog-only / unsupported layout until dedicated driver exists.
        AsicProtocolIdentity::Bm1391 => ProtocolCapabilities {
            get_address_enumerate: false,
            assign_chip_addresses: false,
            work_submit: false,
            frequency_program: false,
            version_rolling_work: false,
        },
        // Desk-proven CRC5 VIL frames exist; work/freq stay refused until
        // am1-s9se has an executor. Transport admit is still false.
        AsicProtocolIdentity::Bm1393 => ProtocolCapabilities {
            get_address_enumerate: true,
            assign_chip_addresses: true,
            work_submit: false,
            frequency_program: false,
            version_rolling_work: false,
        },
        AsicProtocolIdentity::Bm1387 => ProtocolCapabilities {
            get_address_enumerate: true,
            assign_chip_addresses: true,
            work_submit: true,
            frequency_program: true,
            version_rolling_work: false,
        },
        // Exact signed BM1396 binaries prove pure enumeration, address, and
        // PLL contracts. Work-frame/nonce semantics and carrier execution are
        // not complete, so work and version rolling remain refused.
        AsicProtocolIdentity::Bm1396 => ProtocolCapabilities {
            get_address_enumerate: true,
            assign_chip_addresses: true,
            work_submit: false,
            frequency_program: true,
            version_rolling_work: false,
        },
        AsicProtocolIdentity::Bm1362
        | AsicProtocolIdentity::Bm1366
        | AsicProtocolIdentity::Bm1368
        | AsicProtocolIdentity::Bm1370
        | AsicProtocolIdentity::Bm1397
        | AsicProtocolIdentity::Bm1398 => ProtocolCapabilities {
            get_address_enumerate: true,
            assign_chip_addresses: true,
            work_submit: true,
            frequency_program: true,
            version_rolling_work: true,
        },
    }
}

/// Build a minimal pure init program skeleton for an admitted protocol.
///
/// This is **not** a live bring-up sequence — it is a portable narrative so
/// future engines compose the same step kinds. Empty when capabilities refuse
/// enumeration (RuntimeDiscovered / BM1391 catalog refuse).
pub fn plan_pure_init_program(
    admission: ProtocolTransportAdmission,
    chip_count: u8,
    frequency_mhz: u16,
) -> InitProgram {
    let caps = protocol_capabilities(admission.protocol());
    if !caps.get_address_enumerate {
        return InitProgram::default();
    }
    let mut steps = vec![
        InitStep::SoftReset,
        InitStep::DelayMs(100),
        InitStep::EnumerateAtBaud {
            baud_label: "bringup_default",
        },
    ];
    if caps.assign_chip_addresses && chip_count > 0 {
        steps.push(InitStep::AssignAddresses { chip_count });
    }
    if caps.frequency_program && frequency_mhz > 0 {
        steps.push(InitStep::ProgramFrequencyMhz { frequency_mhz });
    }
    InitProgram { steps }
}

impl BoardDesc {
    /// Admit this board's declared protocol over its declared transport.
    pub fn admit_protocol_transport(
        &self,
    ) -> Result<ProtocolTransportAdmission, ProtocolTransportError> {
        admit_protocol_over_transport(self.asic_protocol, self.chain_transport)
    }

    /// Admit protocol×transport **and** work-engine facet together.
    pub fn admit_protocol_transport_and_work_engine(
        &self,
    ) -> Result<ProtocolTransportAdmission, ProtocolTransportError> {
        let admission = self.admit_protocol_transport()?;
        admit_work_engine_over_transport(self.chain_transport, self.work_engine)?;
        Ok(admission)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn management_none_transport_refuses_all_protocols() {
        for protocol in [
            AsicProtocolIdentity::Bm1387,
            AsicProtocolIdentity::Bm1362,
            AsicProtocolIdentity::RuntimeDiscovered,
        ] {
            assert_eq!(
                admit_protocol_over_transport(protocol, ChainTransportKind::None),
                Err(ProtocolTransportError::ManagementOnlyTransport)
            );
        }
    }

    #[test]
    fn runtime_discovered_refuses_even_on_serial() {
        assert_eq!(
            admit_protocol_over_transport(
                AsicProtocolIdentity::RuntimeDiscovered,
                ChainTransportKind::Serial
            ),
            Err(ProtocolTransportError::RuntimeDiscoveredProtocol)
        );
    }

    #[test]
    fn s9_bm1387_fpga_uio_admits() {
        let a = admit_protocol_over_transport(
            AsicProtocolIdentity::Bm1387,
            ChainTransportKind::FpgaUio,
        )
        .expect("S9 path");
        assert_eq!(a.protocol(), AsicProtocolIdentity::Bm1387);
        assert_eq!(a.transport(), ChainTransportKind::FpgaUio);
    }

    #[test]
    fn bm1387_refuses_serial_transport() {
        let err =
            admit_protocol_over_transport(AsicProtocolIdentity::Bm1387, ChainTransportKind::Serial)
                .unwrap_err();
        assert!(matches!(
            err,
            ProtocolTransportError::Incompatible {
                protocol: AsicProtocolIdentity::Bm1387,
                transport: ChainTransportKind::Serial
            }
        ));
    }

    #[test]
    fn bm1362_admits_hybrid_serial_and_uart_trans() {
        assert!(admit_protocol_over_transport(
            AsicProtocolIdentity::Bm1362,
            ChainTransportKind::ZynqHybrid
        )
        .is_ok());
        assert!(admit_protocol_over_transport(
            AsicProtocolIdentity::Bm1362,
            ChainTransportKind::Serial
        )
        .is_ok());
        assert!(admit_protocol_over_transport(
            AsicProtocolIdentity::Bm1362,
            ChainTransportKind::UartTrans
        )
        .is_ok());
        assert!(admit_protocol_over_transport(
            AsicProtocolIdentity::Bm1362,
            ChainTransportKind::FpgaUio
        )
        .is_err());
    }

    #[test]
    fn amlogic_serial_families_admit() {
        for protocol in [
            AsicProtocolIdentity::Bm1366,
            AsicProtocolIdentity::Bm1368,
            AsicProtocolIdentity::Bm1370,
        ] {
            assert!(
                admit_protocol_over_transport(protocol, ChainTransportKind::Serial).is_ok(),
                "{protocol:?}"
            );
        }
    }

    #[test]
    fn bm1391_catalog_identity_refuses_active_transports() {
        assert!(admit_protocol_over_transport(
            AsicProtocolIdentity::Bm1391,
            ChainTransportKind::Serial
        )
        .is_err());
        let caps = protocol_capabilities(AsicProtocolIdentity::Bm1391);
        assert!(!caps.work_submit);
        assert!(!caps.get_address_enumerate);
    }

    #[test]
    fn bm1396_pure_contract_does_not_admit_an_active_carrier_or_work() {
        for transport in [
            ChainTransportKind::FpgaUio,
            ChainTransportKind::StockFpga,
            ChainTransportKind::ZynqHybrid,
            ChainTransportKind::Serial,
            ChainTransportKind::UartTrans,
        ] {
            assert!(
                admit_protocol_over_transport(AsicProtocolIdentity::Bm1396, transport).is_err(),
                "BM1396 must refuse active transport {transport:?}"
            );
        }
        let caps = protocol_capabilities(AsicProtocolIdentity::Bm1396);
        assert!(caps.get_address_enumerate);
        assert!(caps.assign_chip_addresses);
        assert!(caps.frequency_program);
        assert!(!caps.work_submit);
        assert!(!caps.version_rolling_work);

        for target in ["am2-s17e", "am2-t17e"] {
            let desc = BoardDesc::lookup(target).expect("exact BM1396 descriptor");
            assert!(desc.admit_protocol_transport().is_err(), "{target}");
            assert!(
                desc.admit_protocol_transport_and_work_engine().is_err(),
                "{target}"
            );
        }
    }

    #[test]
    fn work_engine_matrix_matches_transports() {
        assert!(admit_work_engine_over_transport(
            ChainTransportKind::FpgaUio,
            WorkEngineKind::FpgaWorkFifo
        )
        .is_ok());
        assert!(admit_work_engine_over_transport(
            ChainTransportKind::Serial,
            WorkEngineKind::SerialWork
        )
        .is_ok());
        assert!(admit_work_engine_over_transport(
            ChainTransportKind::None,
            WorkEngineKind::ManagementOnly
        )
        .is_ok());
        assert!(admit_work_engine_over_transport(
            ChainTransportKind::Serial,
            WorkEngineKind::FpgaWorkFifo
        )
        .is_err());
    }

    #[test]
    fn pure_init_program_skeleton_for_admitted_s9() {
        let admission = admit_protocol_over_transport(
            AsicProtocolIdentity::Bm1387,
            ChainTransportKind::FpgaUio,
        )
        .unwrap();
        let prog = plan_pure_init_program(admission, 63, 500);
        assert!(!prog.is_empty());
        assert!(prog.steps.iter().any(|s| matches!(s, InitStep::SoftReset)));
        assert!(prog
            .steps
            .iter()
            .any(|s| matches!(s, InitStep::AssignAddresses { chip_count: 63 })));
        assert!(prog
            .steps
            .iter()
            .any(|s| matches!(s, InitStep::ProgramFrequencyMhz { frequency_mhz: 500 })));
        // Zero chip/freq still keeps reset+enum; omits assign/freq.
        let minimal = plan_pure_init_program(admission, 0, 0);
        assert!(minimal
            .steps
            .iter()
            .any(|s| matches!(s, InitStep::SoftReset)));
        assert!(!minimal
            .steps
            .iter()
            .any(|s| matches!(s, InitStep::AssignAddresses { .. })));
    }

    #[test]
    fn runtime_discovered_capabilities_are_all_false() {
        let caps = protocol_capabilities(AsicProtocolIdentity::RuntimeDiscovered);
        assert!(!caps.get_address_enumerate);
        assert!(!caps.work_submit);
        assert!(!caps.frequency_program);
    }

    #[test]
    fn every_board_desc_registry_row_is_protocol_transport_consistent() {
        // Composition honesty: protocol×transport pure admit matches BoardDesc.
        // Work-engine ManagementOnly on an active transport is an intentional
        // "identity known, mining not enabled" state — protocol admit may still
        // pass while combined work admit fails closed.
        for desc in BoardDesc::all_registered() {
            let proto = desc.admit_protocol_transport();
            match desc.chain_transport {
                ChainTransportKind::None => {
                    assert!(
                        matches!(proto, Err(ProtocolTransportError::ManagementOnlyTransport)),
                        "{} transport None must refuse: {:?}",
                        desc.board_target,
                        proto
                    );
                }
                _ if matches!(desc.asic_protocol, AsicProtocolIdentity::RuntimeDiscovered) => {
                    assert!(
                        proto.is_err(),
                        "{} RuntimeDiscovered must refuse",
                        desc.board_target
                    );
                }
                _ if matches!(
                    desc.asic_protocol,
                    AsicProtocolIdentity::Bm1391
                        | AsicProtocolIdentity::Bm1393
                        | AsicProtocolIdentity::Bm1396
                ) =>
                {
                    assert!(
                        proto.is_err(),
                        "{} pure-only protocol must refuse active mutation admit",
                        desc.board_target
                    );
                }
                _ => {
                    assert!(
                        proto.is_ok(),
                        "{} protocol×transport must admit: {:?}",
                        desc.board_target,
                        proto
                    );
                }
            }

            let combined = desc.admit_protocol_transport_and_work_engine();
            match (desc.chain_transport, desc.work_engine) {
                (ChainTransportKind::None, WorkEngineKind::ManagementOnly) => {
                    assert!(combined.is_err());
                }
                (_, WorkEngineKind::ManagementOnly) => {
                    // Known identity, mining not enabled — work facet refuses.
                    assert!(
                        combined.is_err(),
                        "{} ManagementOnly on active transport must fail combined admit",
                        desc.board_target
                    );
                }
                _ if proto.is_ok() => {
                    assert!(
                        combined.is_ok(),
                        "{} mining work path must pass combined admit: {:?}",
                        desc.board_target,
                        combined
                    );
                }
                _ => {}
            }
        }
    }

    #[test]
    fn public_beta_s9_and_s19j_xil_compose() {
        let s9 = BoardDesc::lookup("am1-s9").expect("s9");
        s9.admit_protocol_transport_and_work_engine()
            .expect("S9 beta mining composition");
        let xil = BoardDesc::lookup("am2-s19j").expect("s19j xil");
        xil.admit_protocol_transport_and_work_engine()
            .expect("S19j Pro XIL serial-work hybrid composition");
    }
}
