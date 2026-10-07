//! Complete the selected modern AML UART population before admitting any work.
//!
//! Hardware admission still owns the exact routes, GPIO/reset and PSU service.
//! This function shares the real initialization and transport construction with
//! the PTY fault replay; only opening an admitted UART and servicing the retained
//! PSU are supplied by the caller. Failure returns to the caller's joined
//! power/watchdog/serial closeout and never returns a partial work transport.
use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn initialize(
    primary: ValidatedSerialBackend,
    primary_geometry: &ValidatedSerialAssignedGeometry,
    routes: &[(u8, &'static str)],
    identity: dcentrald_common::AsicProtocolIdentity,
    chip_count: u8,
    target_freq: u16,
    policy: IndustrialSerialPllPolicy,
    response_body_len: usize,
    shutdown: &CancellationToken,
    s21_full_unit: Option<dcentrald_common::bm1368_s21_board_profiles::S21FullUnitAccounting>,
    mut heartbeat: impl FnMut() -> Result<()>,
    mut open: impl FnMut(u8, &str) -> Result<SerialChainBackend>,
) -> Result<SerialWorkTransport> {
    use dcentrald_common::AsicProtocolIdentity;
    anyhow::ensure!(
        (1..=3).contains(&routes.len())
            && primary_geometry.identity == identity
            && primary_geometry.observed_chip_count() == chip_count
            && routes
                .first()
                .is_some_and(|(slot, _)| *slot == primary.backend.chain_id()),
        "native AML primary/population geometry mismatch"
    );
    // The wrapper supplies HAL-admitted routes. Validate the complete table
    // before opening any additional port, including physical slot uniqueness.
    for (index, &(slot, path)) in routes.iter().enumerate() {
        anyhow::ensure!(
            slot < 3
                && !routes[..index]
                    .iter()
                    .any(|(prior_slot, prior_path)| { *prior_slot == slot || *prior_path == path }),
            "native AML selected population duplicates a physical UART or slot"
        );
    }
    let execution = primary.execution.clone();
    let mut backends = vec![primary.backend];
    for &(slot, path) in routes.iter().skip(1) {
        anyhow::ensure!(
            !shutdown.is_cancelled(),
            "native AML shutdown before sibling initialization"
        );
        heartbeat()?;
        let backend = execution.commit("native AML selected physical UART open", || {
            anyhow::ensure!(
                !shutdown.is_cancelled(),
                "native AML shutdown before selected UART open"
            );
            open(slot, path)
        })?;
        anyhow::ensure!(
            backend.chain_id() == slot,
            "native AML UART opener returned another physical slot"
        );
        let serial = ValidatedSerialBackend::new(backend, execution.clone())
            .with_am2_energized_cancellation(shutdown.clone());
        let cold = serial.query_cold_chip_address_window(
            identity,
            "native AML selected sibling cold identity",
        )?;
        anyhow::ensure!(
            cold.observed_frames().get() == chip_count
                && cold.shape() == SerialAddressWindowShape::RepeatedUnassignedZero,
            "native AML slot{slot} lacks complete unassigned selected-profile population"
        );
        let (serial, geometry) = match identity {
            AsicProtocolIdentity::Bm1362 => SerialMiner::init_bm1362_aml_chain(
                serial,
                path,
                115_200,
                chip_count,
                target_freq,
                policy,
            )?,
            AsicProtocolIdentity::Bm1366 => SerialMiner::init_bm1366_xp_chain(
                serial,
                path,
                115_200,
                chip_count,
                target_freq,
                policy,
            )?,
            AsicProtocolIdentity::Bm1368 => SerialMiner::init_bm1368_chain(
                serial,
                path,
                115_200,
                chip_count,
                target_freq,
                policy,
            )?,
            AsicProtocolIdentity::Bm1370 => SerialMiner::init_bm1370_chain(
                serial,
                path,
                115_200,
                chip_count,
                target_freq,
                policy,
            )?,
            _ => anyhow::bail!("native AML sibling selected another ASIC family"),
        };
        anyhow::ensure!(
            geometry.identity == primary_geometry.identity
                && geometry.addresses == primary_geometry.addresses
                && geometry.applied_frequency_mhz == primary_geometry.applied_frequency_mhz,
            "native AML slot{slot} initialized geometry/frequency differs from selected profile"
        );
        serial.set_response_len(response_body_len);
        backends.push(serial.backend);
    }
    heartbeat()?;
    anyhow::ensure!(
        !shutdown.is_cancelled(),
        "native AML shutdown before multi-UART work admission"
    );
    execution.commit(
        "native AML complete population RX polling configuration",
        || {
            anyhow::ensure!(
                !shutdown.is_cancelled(),
                "native AML shutdown before RX polling configuration"
            );
            for backend in &backends {
                // SerialChain::open installs VTIME=1 (100ms). Empty reads would
                // otherwise hold the shared execution fence past the nonce poll
                // deadline on every silent UART. VTIME=0 keeps normal blocking TX
                // while the RX loop owns its existing bounded polling deadline.
                backend.set_vtime(0)?;
                backend.set_response_len(response_body_len);
            }
            Ok::<(), anyhow::Error>(())
        },
    )?;
    let multi = MultiTtyTransport {
        paths: routes.iter().map(|(_, path)| *path).collect(),
        tx_required: vec![true; backends.len()],
        backends,
        execution,
        native_exact_mapping: true,
        next: AtomicUsize::new(0),
        last_rx: AtomicUsize::new(0),
        pending_rx: Mutex::new(VecDeque::new()),
        s21_full_unit,
    };
    multi.admit_rx_tables().map_err(anyhow::Error::msg)?;
    Ok(SerialWorkTransport::Multi(multi))
}
