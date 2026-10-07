//! A wake-up request for a daemon that has never constructed hardware.
//!
//! This channel grants no reboot, rail, or hardware-disposition authority.
//! Only the initial idle branch installs it; a hardware-owning process has no
//! receiver. The daemon validates persisted configuration before replacing its
//! own process image with the same PID.

use std::sync::{Arc, OnceLock};
use tokio::sync::Notify;

static COLD_ACTIVATION: OnceLock<Arc<Notify>> = OnceLock::new();

pub fn initial_idle_activation_available() -> bool {
    COLD_ACTIVATION.get().is_some()
}

pub fn install_initial_idle_activation() -> Result<Arc<Notify>, &'static str> {
    let wake = Arc::new(Notify::new());
    COLD_ACTIVATION
        .set(wake.clone())
        .map_err(|_| "initial idle activation already installed")?;
    Ok(wake)
}

/// Returns true only when the initial, hardware-free daemon owns the request.
pub fn request_initial_idle_activation() -> bool {
    match COLD_ACTIVATION.get() {
        Some(wake) => {
            wake.notify_one();
            true
        }
        None => false,
    }
}
