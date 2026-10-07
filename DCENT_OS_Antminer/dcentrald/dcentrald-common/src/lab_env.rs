//! Hardware environment overrides belong only to explicitly compiled lab builds.
//!
//! Callers retain their own parsing and typed production defaults. These adapters
//! preserve `std::env`'s Unicode and presence semantics in a lab build; a normal
//! build never reads the process environment here. Refusal-only scans and
//! operational metadata must continue to use their separate raw readers.

use std::env::VarError;
use std::ffi::OsString;

/// Also detects dependency feature unification: every hardware crate's `lab`
/// feature forwards here. Signed Beta/Stable admission must reject this value.
pub const fn compiled() -> bool {
    cfg!(feature = "lab")
}

/// Read a hardware override only when the common lab capability is compiled.
#[cfg(feature = "lab")]
pub fn var(name: &str) -> Result<String, VarError> {
    std::env::var(name)
}

#[cfg(not(feature = "lab"))]
pub fn var(_name: &str) -> Result<String, VarError> {
    Err(VarError::NotPresent)
}

/// Presence remains distinct from truthiness, including empty/non-Unicode values.
#[cfg(feature = "lab")]
pub fn var_os(name: &str) -> Option<OsString> {
    std::env::var_os(name)
}

#[cfg(not(feature = "lab"))]
pub fn var_os(_name: &str) -> Option<OsString> {
    None
}
