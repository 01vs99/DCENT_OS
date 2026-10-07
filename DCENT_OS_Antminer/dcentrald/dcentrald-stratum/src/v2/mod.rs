//! Stratum V2 protocol support.
//!
//! Native SV2 Mining Device client with Noise_NX encryption.
//! Ported from the proven DCENT_axe (ESP32) implementation.
//!
//! # Honesty (DESK_NOW rank 12)
//!
//! This client is **opt-in** (`protocol = "sv2"` / `"v2"`, or Auto with a
//! pool `sv2_url`). Host mock-pool and independent SRI-library interoperability harnesses exist. **Live accepted shares
//! are BENCH_HOLD** — not a production SV2 mining path and **not
//! Braiins-parity** Job Declaration. JD `probe_once` is a supervisor
//! connectivity probe (opt-in, `JdConfig.enabled` default false), not
//! mining-work injection. OCEAN DATUM is not implemented.

#[cfg(feature = "sv2")]
pub mod adapter;
#[cfg(feature = "sv2")]
pub mod auth;
#[cfg(feature = "sv2")]
pub mod channel;
#[cfg(feature = "sv2")]
pub mod client;
#[cfg(feature = "sv2")]
pub mod difficulty_autotune;
#[cfg(feature = "sv2")]
pub mod framing;
#[cfg(feature = "sv2")]
pub mod noise;
#[cfg(feature = "sv2")]
pub mod types;

#[cfg(feature = "jd")]
pub mod jd;

// W9.3 — mock SV2 pool harness (OCEAN + DEMAND/SRI styles). Compiled
// only when `mock-pool` feature is on, which is exclusively turned on
// by the `tests/sv2_multi_pool.rs` integration test and the
// `cross-compile-matrix.yml` `sv2-mock-pool-tests` CI cell. Never
// enabled in production sysupgrade tarballs.
#[cfg(all(feature = "sv2", feature = "mock-pool"))]
pub mod test_server;
