use super::*;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::time::Duration;

fn pty() -> (SerialChainBackend, File, File) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: two initialized output pointers for fresh local PTY descriptors;
    // no optional name/config pointers and no physical UART access.
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    // SAFETY: each independently returned descriptor is adopted exactly once.
    let master = unsafe { File::from_raw_fd(master) };
    // SAFETY: this fresh slave descriptor has not otherwise been adopted.
    let slave = unsafe { File::from_raw_fd(slave) };
    let backend = SerialChainBackend::open_native_linux_only(
        0,
        &format!("/proc/self/fd/{}", slave.as_raw_fd()),
        115200,
    )
    .unwrap();
    (backend, master, slave)
}
fn due() -> Instant {
    Instant::now() + Duration::from_secs(1)
}
fn nonce() -> Vec<u8> {
    vec![0xaa, 0x55, 1, 2, 3, 4, 0, 0x80, 0x12, 0x34, 0x80]
}
fn input_ready(slave: &File) {
    let mut item = libc::pollfd {
        fd: slave.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: initialized pollfd for one retained local PTY and bounded timeout.
    assert_eq!(unsafe { libc::poll(&mut item, 1, 500) }, 1);
}

#[test]
fn same_pty_sends_exact_raw_frame_receives_held_fragments_and_preserves_pacing_ring() {
    let (backend, mut master, slave) = pty();
    let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    let frame: Vec<u8> = (0..88).map(|v| v as u8).collect();
    let sent = owner.try_send_raw_until(0, &frame, 40, 0, due());
    assert_eq!(sent.dispatch, Ok(true));
    assert_eq!(sent.io.unwrap().accepted_prefix, frame);
    let mut actual = [0; 88];
    master.read_exact(&mut actual).unwrap();
    assert_eq!(actual.as_slice(), frame);
    let ring = owner.in_flight_ring(0);
    let mut held = owner.hold_dispatch().unwrap();
    let wire = nonce();
    master.write_all(&wire[..5]).unwrap();
    input_ready(&slave);
    let first = held.receive_until(due());
    assert!(first.parsed.caller_completed && first.parsed.nonces.is_empty());
    assert_eq!(first.io.len(), 1);
    assert_eq!(first.io[0].1.bytes, wire[..5]);
    master.write_all(&wire[5..]).unwrap();
    input_ready(&slave);
    let second = held.receive_until(due());
    assert!(second.parsed.caller_completed);
    assert_eq!(second.parsed.nonces.len(), 1);
    assert_eq!(second.parsed.nonces[0].1.raw_frame.as_slice(), wire);
    assert!(held.snapshot().held && !held.snapshot().send_caller_pending);
    held.resume().unwrap();
    assert_eq!(owner.in_flight_ring(0), ring);
    let paced = owner.try_send_raw_until(0, &[9, 8], 42, 1, due());
    assert_eq!(paced.dispatch, Ok(false));
    assert!(paced.io.is_none());
}

#[test]
fn expired_send_retains_zero_io_attempt_and_permanently_prevents_fresh_retry() {
    let (backend, master, _slave) = pty();
    let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    let result = owner.try_send_raw_until(0, &[1, 2, 3], 2, 0, Instant::now());
    assert_eq!(
        result.dispatch,
        Err(DispatchError::Transport(UartTransportError::WriteFailed))
    );
    let io = result.io.unwrap();
    assert_eq!(io.status.io_calls, 0);
    assert_eq!(io.accepted_bytes, 0);
    assert!(io.status.failure.as_ref().unwrap().contains("deadline"));
    assert!(owner.snapshot().permanently_stopped);
    assert!(owner.in_flight_ring(0).unwrap().iter().all(Option::is_none));
    let retry = owner.try_send_raw_until(0, &[4, 5, 6], 3, 20_000, due());
    assert_eq!(retry.dispatch, Err(DispatchError::Stopped));
    assert!(retry.io.is_none());
    assert!(owner.inner.transport.chains[0]
        .last_write
        .as_ref()
        .unwrap()
        .status
        .failure
        .is_some());
    let mut item = libc::pollfd {
        fd: master.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: initialized pollfd for the retained software peer, no wait.
    assert_eq!(unsafe { libc::poll(&mut item, 1, 0) }, 0);
}

#[test]
fn actual_partial_write_is_retained_inside_terminal_owner_and_cannot_be_retried() {
    let (backend, mut master, _slave) = pty();
    let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    // Oversized raw bytes are a software backpressure fixture, not an ASIC frame.
    let frame = vec![0x36; 1024 * 1024];
    let result =
        owner.try_send_raw_until(0, &frame, 40, 0, Instant::now() + Duration::from_millis(40));
    assert!(result.dispatch.is_err());
    let io = result.io.unwrap();
    assert!(io.accepted_bytes > 0 && io.accepted_bytes < frame.len());
    assert_eq!(io.accepted_prefix, frame[..io.accepted_bytes]);
    assert!(io.status.caller_completed_at.is_none() && io.status.flags_restored);
    let mut actual = vec![0; io.accepted_bytes];
    master.read_exact(&mut actual).unwrap();
    assert_eq!(actual, io.accepted_prefix);
    assert!(owner.snapshot().permanently_stopped);
    assert!(owner.in_flight_ring(0).unwrap().iter().all(Option::is_none));
    let retry = owner.try_send_raw_until(0, &[1, 2], 42, 20_000, due());
    assert_eq!(retry.dispatch, Err(DispatchError::Stopped));
    assert!(retry.io.is_none());
    assert_eq!(
        owner.inner.transport.chains[0]
            .last_write
            .as_ref()
            .unwrap()
            .accepted_prefix,
        actual
    );
}

#[test]
fn expired_held_receive_retains_actual_failure_and_refuses_resume_without_consuming_input() {
    let (backend, mut master, slave) = pty();
    let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    master.write_all(&nonce()).unwrap();
    input_ready(&slave);
    let mut held = owner.hold_dispatch().unwrap();
    let result = held.receive_until(Instant::now());
    assert!(result.parsed.failure.is_some() && result.parsed.nonces.is_empty());
    assert_eq!(result.io.len(), 1);
    assert_eq!(result.io[0].1.status.io_calls, 0);
    assert!(result.io[0].1.returned_count.is_none());
    assert_eq!(held.resume(), Err(DispatchError::Stopped));
    input_ready(&slave);
    let again = owner.receive_until(due());
    assert!(again.io.is_empty() && again.parsed.failure.is_some());
    assert!(owner.inner.transport.chains[0]
        .last_read
        .as_ref()
        .unwrap()
        .status
        .failure
        .is_some());
}

#[test]
fn shared_terminal_publisher_closes_all_admission_without_consuming_pending_input() {
    let (first, mut master, slave) = pty();
    let (second, _master2, _slave2) = pty();
    let mut owner = BbSerialDispatchOwner::new(vec![first, second], 20_000);
    master.write_all(&nonce()).unwrap();
    input_ready(&slave);
    let stop = owner.stop_handle();
    stop.stop();
    let received = owner.receive_until(due());
    assert!(received.io.is_empty() && received.parsed.reads.is_empty());
    for chain in 0..2 {
        let result = owner.try_send_raw_until(chain, &[1, 2], 3, 0, due());
        assert_eq!(result.dispatch, Err(DispatchError::Stopped));
        assert!(result.io.is_none());
    }
    input_ready(&slave);
    assert!(owner
        .inner
        .transport
        .chains
        .iter()
        .all(|uart| uart.stop.snapshot().permanently_stopped));
    drop(owner);
    assert!(stop.snapshot().permanently_stopped);
}

#[test]
fn actual_peer_hangup_write_failure_keeps_hal_detail_and_original_owner() {
    let (backend, master, _slave) = pty();
    drop(master);
    let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    let sent = owner.try_send_raw_until(0, &[1, 2, 3], 40, 0, due());
    assert!(sent.dispatch.is_err());
    let io = sent.io.unwrap();
    assert_eq!(io.status.io_calls, 1);
    assert_eq!(io.accepted_bytes, 0);
    assert!(io.status.failure.is_some() && io.status.flags_restored);
    assert!(owner.snapshot().permanently_stopped);
    assert_eq!(owner.inner.chain_count(), 1);
    assert!(owner.inner.transport.chains[0]
        .last_write
        .as_ref()
        .unwrap()
        .status
        .failure
        .is_some());
}
