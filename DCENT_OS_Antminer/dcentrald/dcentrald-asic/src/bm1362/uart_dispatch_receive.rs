//! One checked read per owned chain per poll, using the existing shared parser.
//! Count-bounded polling cannot interrupt an already-started backend read. The
//! enclosing runtime must retain its caller and original UART lifetime.
use super::super::Bm1362SerialNonce;
use super::*;

/// Native receiver adapters must preserve backend errors. The legacy usize-only
/// read method remains available to compatibility callers, with its old behavior.
pub(crate) trait CheckedChainUart: ChainUart {
    fn read_avail_checked(&mut self, bytes: &mut [u8]) -> CheckedRead;
}

/// A successful backend read can be followed by an error in cancellation,
/// deadline or flag restoration. Keep both facts without claiming completion.
#[derive(Clone, Debug)]
pub(crate) struct CheckedRead {
    pub returned_count: Option<usize>,
    pub failure: Option<String>,
}

impl From<Result<usize, String>> for CheckedRead {
    fn from(value: Result<usize, String>) -> Self {
        match value {
            Ok(n) => Self {
                returned_count: Some(n),
                failure: None,
            },
            Err(error) => Self {
                returned_count: None,
                failure: Some(error),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ReceiveError {
    Admission(DispatchError),
    Read {
        chain: usize,
        detail: String,
    },
    InvalidCount {
        chain: usize,
        reported: usize,
        capacity: usize,
    },
    Stopped,
}

#[derive(Clone, Debug)]
pub(crate) struct ReceiveRead {
    pub chain: usize,
    pub returned_count: Option<usize>,
    /// Normal reads retain exactly the returned prefix. An invalid oversized
    /// count retains only the scratch buffer as observed, not nonexistent bytes.
    pub returned_prefix: Option<Vec<u8>>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct ReceiveAttempt {
    pub reads: Vec<ReceiveRead>,
    pub nonces: Vec<(usize, Bm1362SerialNonce)>,
    /// All selected owned chains were polled while admission remained live.
    /// This is neither a task join, physical freshness nor validated shares.
    pub caller_completed: bool,
    pub failure: Option<ReceiveError>,
}

struct ReceiveScope {
    stop: DispatchStop,
    completed: bool,
}

impl ReceiveScope {
    fn enter(stop: &DispatchStop, held: bool) -> Result<Self, DispatchError> {
        let expected = if held { HELD } else { 0 };
        stop.state
            .compare_exchange(
                expected,
                expected | RECEIVE,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map_err(|value| {
                if value & STOPPED != 0 {
                    DispatchError::Stopped
                } else {
                    DispatchError::HeldOrPending
                }
            })?;
        Ok(Self {
            stop: stop.clone(),
            completed: false,
        })
    }
}

impl Drop for ReceiveScope {
    fn drop(&mut self) {
        if !self.completed {
            self.stop.stop();
        }
        self.stop.state.fetch_and(!RECEIVE, Ordering::SeqCst);
    }
}

impl<U: CheckedChainUart> BbDispatchOwner<U> {
    pub(crate) fn receive_once(&mut self) -> ReceiveAttempt {
        self.receive_scoped(false)
    }

    pub(super) fn receive_scoped(&mut self, held: bool) -> ReceiveAttempt {
        let mut result = ReceiveAttempt {
            reads: Vec::new(),
            nonces: Vec::new(),
            caller_completed: false,
            failure: None,
        };
        let mut scope = match ReceiveScope::enter(&self.stop, held) {
            Ok(scope) => scope,
            Err(error) => {
                result.failure = Some(ReceiveError::Admission(error));
                return result;
            }
        };
        for chain in 0..self.transport.chains.len() {
            if self.stop.snapshot().permanently_stopped {
                result.failure = Some(ReceiveError::Stopped);
                return result;
            }
            let read =
                self.transport.chains[chain].read_avail_checked(&mut self.transport.rx_scratch);
            result.reads.push(ReceiveRead {
                chain,
                returned_count: read.returned_count,
                returned_prefix: read.returned_count.map(|n| {
                    self.transport.rx_scratch[..n.min(self.transport.rx_scratch.len())].to_vec()
                }),
                error: read.failure.clone(),
            });
            let n = match read.returned_count {
                Some(n) if n <= self.transport.rx_scratch.len() => n,
                Some(n) => {
                    result.failure = Some(ReceiveError::InvalidCount {
                        chain,
                        reported: n,
                        capacity: self.transport.rx_scratch.len(),
                    });
                    return result;
                }
                None => {
                    let detail = read
                        .failure
                        .unwrap_or_else(|| "checked read returned neither count nor error".into());
                    result.reads.last_mut().expect("just recorded read").error =
                        Some(detail.clone());
                    result.failure = Some(ReceiveError::Read { chain, detail });
                    return result;
                }
            };
            self.transport.rx_bm1362_serial[chain]
                .extend_from_slice(&self.transport.rx_scratch[..n]);
            self.transport.rx_bm1362_serial_raw_bytes[chain] += n as u64;
            // Preserve frames actually returned by a read admitted before stop.
            // They remain raw historical candidates, not new dispatch authority.
            self.transport
                .parse_bm1362_serial_buffer(chain, &mut result.nonces);
            if let Some(detail) = read.failure {
                result.failure = Some(ReceiveError::Read { chain, detail });
                return result;
            }
            if self.stop.snapshot().permanently_stopped {
                result.failure = Some(ReceiveError::Stopped);
                return result;
            }
        }
        if self.stop.snapshot().permanently_stopped {
            result.failure = Some(ReceiveError::Stopped);
            return result;
        }
        result.caller_completed = true;
        scope.completed = true;
        result
    }
}

impl<U: CheckedChainUart> DispatchHold<'_, U> {
    pub(crate) fn receive_once(&mut self) -> ReceiveAttempt {
        self.owner.receive_scoped(true)
    }
}

#[cfg(test)]
#[path = "uart_dispatch_receive_tests.rs"]
mod tests;
