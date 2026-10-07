//! Passive Stratum hint input. These values never authorize hardware writes or
//! replace measured hashrate. The runtime must supply observed geometry and
//! frequencies whose existing hardware operation completed successfully.
use dcentrald_stratum::v1::policy::ActiveCapacity;
use tokio::sync::watch;

pub(crate) struct CapacityPublisher(Option<watch::Sender<ActiveCapacity>>);

impl CapacityPublisher {
    pub(crate) fn new(enabled: bool) -> (Self, Option<watch::Receiver<ActiveCapacity>>) {
        if enabled {
            let (tx, rx) = watch::channel(ActiveCapacity {
                hashes_per_second: 0.0,
            });
            (Self(Some(tx)), Some(rx))
        } else {
            (Self(None), None)
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.0.is_some()
    }

    pub(crate) fn publish(&self, admitted: bool, chip_id: u16, chains: &[(u32, u16)]) {
        let Some(tx) = &self.0 else { return };
        let hashes_per_second = if admitted {
            dcentrald_asic::drivers::MinerProfile::for_chip(chip_id)
                .map(|profile| {
                    chains
                        .iter()
                        .map(|(chips, mhz)| {
                            f64::from(*chips)
                                * f64::from(*mhz)
                                * f64::from(profile.ghs_per_mhz)
                                * 1e9
                        })
                        .sum()
                })
                .unwrap_or(0.0)
        } else {
            0.0
        };
        tx.send_if_modified(|current| {
            if current.hashes_per_second == hashes_per_second {
                false
            } else {
                current.hashes_per_second = hashes_per_second;
                true
            }
        });
    }
}

impl Drop for CapacityPublisher {
    fn drop(&mut self) {
        self.publish(false, 0, &[]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_requires_admission_and_is_withdrawn_on_exit() {
        let (publisher, rx) = CapacityPublisher::new(true);
        let rx = rx.unwrap();
        publisher.publish(false, 0x1362, &[(126, 525)]);
        assert_eq!(rx.borrow().hashes_per_second, 0.0);
        publisher.publish(true, 0x1362, &[(63, 400), (63, 500)]);
        let original = rx.borrow().hashes_per_second;
        assert!(original > 0.0);
        publisher.publish(true, 0x1362, &[(63, 400)]);
        assert!(rx.borrow().hashes_per_second < original);
        drop(publisher);
        assert_eq!(rx.borrow().hashes_per_second, 0.0);
    }
}
