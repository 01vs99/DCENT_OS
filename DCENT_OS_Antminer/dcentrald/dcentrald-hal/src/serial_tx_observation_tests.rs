use super::*;
use std::cell::Cell;
use std::time::Duration;

#[test]
fn software_queue_and_transmitter_reports_must_both_be_empty_in_the_same_poll() {
    let mut values = [(1, 1), (0, 0), (0, 1)].into_iter();
    let result = observe_until(
        BackendKind::Kernel,
        Instant::now() + Duration::from_secs(1),
        &|| false,
        |reading| {
            let (pending, status) = values.next().unwrap();
            reading.pending_output = Some(pending);
            reading.line_status = Some(status);
            Ok(())
        },
    );
    assert_eq!(result.polls, 3);
    assert!(result.failure.is_none() && result.caller_completed_at.is_some());
    assert_eq!(
        (result.last.pending_output, result.last.line_status),
        (Some(0), Some(1))
    );
}

#[test]
fn mmio_requires_both_holding_and_shift_register_empty_bits() {
    let mut statuses = [0, 0x20, 0x40, 0x60].into_iter();
    let result = observe_until(
        BackendKind::Mmio,
        Instant::now() + Duration::from_secs(1),
        &|| false,
        |reading| {
            reading.line_status = statuses.next();
            Ok(())
        },
    );
    assert_eq!(result.polls, 4);
    assert!(result.failure.is_none() && result.caller_completed_at.is_some());
    assert_eq!(result.last.line_status, Some(0x60));
    assert!(result.last.pending_output.is_none());
}

#[test]
fn new_partial_error_does_not_reuse_fields_from_an_earlier_complete_poll() {
    let mut count = 0;
    let result = observe_until(
        BackendKind::Kernel,
        Instant::now() + Duration::from_secs(1),
        &|| false,
        |reading| {
            count += 1;
            reading.pending_output = Some(if count == 1 { 1 } else { 0 });
            if count == 1 {
                reading.line_status = Some(1);
                Ok(())
            } else {
                Err(HalError::Io(std::io::Error::from_raw_os_error(
                    libc::ENOTTY,
                )))
            }
        },
    );
    assert_eq!(result.polls, 2);
    assert!(result.caller_completed_at.is_none() && result.failure.is_some());
    assert_eq!(result.last.pending_output, Some(0));
    assert!(result.last.line_status.is_none());
}

#[test]
fn expired_and_cancelled_admission_never_queries_a_backend() {
    for cancelled in [false, true] {
        let deadline = if cancelled {
            Instant::now() + Duration::from_secs(1)
        } else {
            Instant::now()
        };
        let result = observe_until(BackendKind::Kernel, deadline, &|| cancelled, |_| {
            panic!("unadmitted I/O")
        });
        assert_eq!(result.polls, 0);
        assert!(
            result.last.observed_at.is_none()
                && result.last.line_status.is_none()
                && result.last.pending_output.is_none()
        );
        assert!(result.failure.is_some() && result.caller_completed_at.is_none());
    }
}

#[test]
fn cancellation_during_status_read_keeps_raw_result_without_success() {
    let cancelled = Cell::new(false);
    let result = observe_until(
        BackendKind::Kernel,
        Instant::now() + Duration::from_secs(1),
        &|| cancelled.get(),
        |reading| {
            reading.pending_output = Some(0);
            reading.line_status = Some(1);
            cancelled.set(true);
            Ok(())
        },
    );
    assert_eq!(result.polls, 1);
    assert_eq!(result.last.line_status, Some(1));
    assert!(result.failure.unwrap().contains("cancelled"));
    assert!(result.caller_completed_at.is_none());
}

#[test]
fn started_status_call_can_return_after_deadline_without_a_false_completed_drain() {
    let deadline = Instant::now() + Duration::from_millis(5);
    let result = observe_until(BackendKind::Kernel, deadline, &|| false, |reading| {
        std::thread::sleep(Duration::from_millis(20));
        reading.pending_output = Some(0);
        reading.line_status = Some(1);
        Ok(())
    });
    assert_eq!(result.polls, 1);
    assert_eq!(result.deadline, deadline);
    assert!(result.last.observed_at.unwrap() >= deadline);
    assert!(result.failure.unwrap().contains("deadline"));
    assert!(result.caller_completed_at.is_none());
}
