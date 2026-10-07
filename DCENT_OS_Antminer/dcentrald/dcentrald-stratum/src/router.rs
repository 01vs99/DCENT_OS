//! Stratum protocol router: selects V1 or V2 client based on configuration.
//!
//! The router is the top-level entry point for the stratum subsystem. It reads
//! the `protocol` field from `StratumConfig` and dispatches to the appropriate
//! client implementation:
//!
//! - `V1Only` (default): Uses `StratumV1Client` — standard Stratum V1 over TCP.
//! - `V2Only`: Uses `StratumV2Client` — encrypted SV2 with Noise_NX handshake.
//! - `Auto`: Resolves protocol from the active pool's own fields first, then
//!   falls back to the global setting.
//!
//! Both clients share the same channel interface (job_tx, share_rx, status_tx),
//! so the daemon doesn't need to know which protocol is in use.
//!
//! # Backward Compatibility
//!
//! If no `protocol` field is present in config (or it's set to "sv1"/"v1"),
//! the router defaults to V1. Existing configs with no SV2 fields work unchanged.
//!
//! # Future Work
//!
//! - Cross-protocol failover between pool endpoints within one long-lived client
//! - Connection quality metrics for protocol switching decisions
//!
//! # V2Only fail-closed (DESK_NOW rank 12)
//!
//! `protocol = "sv2"` / `"v2"` is single-pool and **will not** silently speak
//! Stratum V1. A configured backup that is missing an SV2 endpoint or is
//! V1-incompatible is **refused** ([`validate_v2_only_contract`]). Live SV2
//! accepted shares remain BENCH_HOLD; this is not Braiins-parity.

#[cfg(feature = "sv2")]
use crate::types::PoolConfig;
use crate::types::{
    refuse_datum_protocol, JobTemplate, StratumConfig, StratumState, StratumStatus, ValidShare,
};
use crate::StratumV1Client;
#[cfg(feature = "sv2")]
use crate::StratumV2Client;
use tokio::sync::mpsc;
#[cfg(all(feature = "sv2", feature = "jd"))]
use tokio::sync::watch;
use tracing::{error, info, warn};

// Hard Standard ceiling + soft Extended preference: shared with types so P2-9
// resolve helpers and the router cannot drift (see
//  — S9 13 TH/s exhausts Standard in ~2.5s).
// Daemon `build_stratum_config` now fills `nominal_hashrate_ghs` from
// MinerProfile when `mining.model` is set; 0.0 remains UnsetZero without a model.
use crate::types::SV2_EXTENDED_CHANNEL_PREFER_HASHRATE_GHS;
#[cfg(any(feature = "sv2", test))]
use crate::types::SV2_STANDARD_CHANNEL_MAX_HASHRATE_GHS;

/// Protocol selection mode, derived from config at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolMode {
    /// Stratum V1 only (default, backward compatible).
    V1Only,
    /// Stratum V2 only (encrypted, Noise_NX transport). Single-pool;
    /// missing/V1 backups and silent V1 fallback are refused.
    V2Only,
    /// Auto-detect: try V2 if sv2_url is configured, else V1.
    Auto,
}

impl std::fmt::Display for ProtocolMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolMode::V1Only => write!(f, "v1"),
            ProtocolMode::V2Only => write!(f, "v2"),
            ProtocolMode::Auto => write!(f, "auto"),
        }
    }
}

/// Stratum protocol router.
///
/// Selects and runs the appropriate stratum client based on the configured
/// protocol mode. Acts as a drop-in replacement for direct `StratumV1Client`
/// usage in the daemon.
pub struct StratumRouter {
    config: StratumConfig,
    protocol_mode: ProtocolMode,
    capacity_rx: Option<tokio::sync::watch::Receiver<crate::v1::policy::ActiveCapacity>>,
    #[cfg(all(feature = "sv2", feature = "jd"))]
    jd_status_rx: Option<watch::Receiver<crate::v2::jd::JdStatus>>,
}

impl StratumRouter {
    fn parse_protocol_mode(protocol: Option<&str>) -> Option<ProtocolMode> {
        match protocol {
            Some("sv2") | Some("v2") => Some(ProtocolMode::V2Only),
            Some("auto") => Some(ProtocolMode::Auto),
            Some("sv1") | Some("v1") => Some(ProtocolMode::V1Only),
            _ => None,
        }
    }

    #[cfg(any(feature = "sv2", test))]
    fn protocol_mode_for_pool(&self, pool: &crate::types::PoolConfig) -> ProtocolMode {
        match Self::parse_protocol_mode(pool.protocol.as_deref()) {
            Some(ProtocolMode::Auto) => {
                if pool.sv2_url.is_some() {
                    ProtocolMode::V2Only
                } else {
                    ProtocolMode::V1Only
                }
            }
            Some(mode) => mode,
            None => match self.protocol_mode {
                ProtocolMode::Auto => {
                    if pool.sv2_url.is_some() {
                        ProtocolMode::V2Only
                    } else {
                        ProtocolMode::V1Only
                    }
                }
                ref mode => mode.clone(),
            },
        }
    }

    /// Create a new router from stratum configuration.
    ///
    /// The protocol mode is determined by the `protocol` field in config:
    /// - `"sv2"` or `"v2"` -> V2Only
    /// - `"auto"` -> Auto (resolve from the active pool endpoint)
    /// - `"sv1"` or `"v1"` -> V1Only (operator-pinned legacy)
    /// - absent / unrecognized -> Auto (W5.3 new default)
    ///
    /// W5.3: previously the absent/unrecognized default was V1Only. Operators
    /// running fresh installs now get Auto, which only flips a session to V2
    /// when the active pool actually advertises an SV2 endpoint
    /// (`pool.sv2_url` set), so legacy V1-only pool configs keep mining over
    /// V1 with no behavioral change. Operators with explicit `protocol = "sv1"`
    /// in their existing configs are still pinned to V1Only — only the
    /// silent default moves.
    pub fn new(config: StratumConfig) -> Self {
        let protocol_mode =
            Self::parse_protocol_mode(config.protocol.as_deref()).unwrap_or(ProtocolMode::Auto);

        info!(
            mode = %protocol_mode,
            "Stratum router initialized"
        );

        Self {
            config,
            protocol_mode,
            capacity_rx: None,
            #[cfg(all(feature = "sv2", feature = "jd"))]
            jd_status_rx: None,
        }
    }

    #[cfg(all(feature = "sv2", feature = "jd"))]
    pub fn with_job_declaration_status_rx(
        mut self,
        rx: watch::Receiver<crate::v2::jd::JdStatus>,
    ) -> Self {
        self.jd_status_rx = Some(rx);
        self
    }

    pub fn with_capacity_rx(
        mut self,
        rx: tokio::sync::watch::Receiver<crate::v1::policy::ActiveCapacity>,
    ) -> Self {
        self.capacity_rx = Some(rx);
        self
    }

    /// Get the selected protocol mode.
    pub fn protocol_mode(&self) -> &ProtocolMode {
        &self.protocol_mode
    }

    #[cfg(any(feature = "sv2", test))]
    fn sv2_standard_channel_block_reason(config: &StratumConfig) -> Option<&'static str> {
        if config.nominal_hashrate_ghs > SV2_STANDARD_CHANNEL_MAX_HASHRATE_GHS
            && !config.sv2_extended_channel
        {
            Some("SV2 Standard channels exhaust nonce space above 1 TH/s; enable Extended/JD or use V1")
        } else {
            None
        }
    }

    /// W5.3: returns true when the configured nominal hashrate sits at or above
    /// the Extended-channel preference threshold.
    ///
    /// The router uses this hint to log the Extended-channel preference and to
    /// help future SV2 channel-open code path-pick `OpenExtendedMiningChannel`
    /// before falling back to Standard. The decision is deliberately keyed off
    /// `StratumConfig::nominal_hashrate_ghs`, which the daemon now fills from
    /// the active silicon profile (`silicon_profile.expected_hashrate_ghs`).
    ///
    /// This is independent of `sv2_standard_channel_block_reason`: the block
    /// reason is the hard "Standard cannot work here" gate at >1 TH/s; this
    /// hint is the soft "Extended is the smarter open" preference at >=5 TH/s.
    pub fn sv2_should_prefer_extended_channel(config: &StratumConfig) -> bool {
        config.nominal_hashrate_ghs >= SV2_EXTENDED_CHANNEL_PREFER_HASHRATE_GHS
    }

    /// True when `protocol` selects V2Only (`sv2` / `v2`).
    pub fn is_v2_only_protocol(protocol: Option<&str>) -> bool {
        matches!(
            Self::parse_protocol_mode(protocol),
            Some(ProtocolMode::V2Only)
        )
    }
}

/// An endpoint can speak SV2 if it has `protocol=sv2/v2` or a non-empty `sv2_url`.
pub fn endpoint_is_sv2_capable(protocol: Option<&str>, sv2_url: Option<&str>) -> bool {
    let proto = protocol.map(str::trim).unwrap_or("");
    let sv2 = sv2_url.map(str::trim).unwrap_or("");
    matches!(proto, "sv2" | "v2") || !sv2.is_empty()
}

/// Fail-closed V2Only backup-pool contract (DESK_NOW rank 12).
///
/// If the primary is V2-only, a configured backup that is missing an SV2
/// endpoint or is V1-incompatible is refused — we will not silently ignore
/// it or speak Stratum V1 on it. SV2-capable backups are also refused
/// because V2Only is single-pool (no SV2 multi-pool failover; live shares
/// BENCH_HOLD). Use `protocol=auto` for V1 failover.
///
/// `backups` entries are `(label, protocol, sv2_url)` for each configured
/// failover endpoint (omit unconfigured slots).
pub fn v2_only_backup_refusal(
    global_protocol: Option<&str>,
    backups: &[(&str, Option<&str>, Option<&str>)],
) -> Result<(), String> {
    if !StratumRouter::is_v2_only_protocol(global_protocol) {
        return Ok(());
    }
    if let Some((label, protocol, sv2_url)) = backups.first() {
        if !endpoint_is_sv2_capable(*protocol, *sv2_url) {
            return Err(format!(
                "protocol=sv2/v2 (V2Only) refused: backup {label} is missing an SV2 endpoint \
                 or is V1-incompatible. V2Only will not silently use Stratum V1 on a backup. \
                 Remove the backup, give it sv2_url/protocol=sv2, or use protocol=auto for V1 failover"
            ));
        }
        return Err(format!(
            "protocol=sv2/v2 (V2Only) is single-pool: backup {label} is configured but SV2 \
             multi-pool failover is not implemented (live accepted shares BENCH_HOLD, not \
             Braiins-parity). Remove backups or use protocol=auto"
        ));
    }
    Ok(())
}

/// Full V2Only contract for a [`StratumConfig`]: DATUM refuse, backup-pool
/// fail-closed, and no silent V1 fallback (Standard-channel block or
/// missing `sv2` feature).
pub fn validate_v2_only_contract(config: &StratumConfig) -> Result<(), String> {
    refuse_datum_protocol(config.protocol.as_deref())?;
    refuse_datum_protocol(config.pool1.protocol.as_deref())?;
    if let Some(pool) = config.pool2.as_ref() {
        refuse_datum_protocol(pool.protocol.as_deref())?;
    }
    if let Some(pool) = config.pool3.as_ref() {
        refuse_datum_protocol(pool.protocol.as_deref())?;
    }

    if !StratumRouter::is_v2_only_protocol(config.protocol.as_deref()) {
        return Ok(());
    }

    #[cfg(not(feature = "sv2"))]
    {
        Err(
            "protocol=sv2/v2 (V2Only) refused: SV2 is not compiled in (feature 'sv2' disabled); \
             will not silently speak Stratum V1"
                .to_string(),
        )
    }

    #[cfg(feature = "sv2")]
    {
        if let Some(reason) = StratumRouter::sv2_standard_channel_block_reason(config) {
            return Err(format!(
                "protocol=sv2/v2 (V2Only) refused: {reason}. V2Only will not silently fall back to \
                 Stratum V1; set sv2_extended_channel=true, lower nominal_hashrate_ghs, or use protocol=auto"
            ));
        }

        let mut backups: Vec<(&str, Option<&str>, Option<&str>)> = Vec::new();
        push_backup(&mut backups, "pool2", config.pool2.as_ref());
        push_backup(&mut backups, "pool3", config.pool3.as_ref());
        v2_only_backup_refusal(config.protocol.as_deref(), &backups)
    }
}

#[cfg(feature = "sv2")]
fn push_backup<'a>(
    backups: &mut Vec<(&'a str, Option<&'a str>, Option<&'a str>)>,
    label: &'a str,
    pool: Option<&'a PoolConfig>,
) {
    if let Some(pool) = pool {
        backups.push((label, pool.protocol.as_deref(), pool.sv2_url.as_deref()));
    }
}

impl StratumRouter {
    /// Run the stratum client with protocol selection.
    ///
    /// This is the main entry point — spawn as a tokio task. The router
    /// selects the appropriate client and delegates to it. The selected
    /// client runs forever with internal reconnection logic.
    ///
    /// # Channel Interface
    /// Same as `StratumV1Client::run()` and `StratumV2Client::run()`:
    /// - `job_tx`: Sends `JobTemplate` when new mining jobs arrive from pool
    /// - `share_rx`: Receives `ValidShare` from the work dispatcher for submission
    /// - `status_tx`: Sends `StratumStatus` updates (state changes, share results)
    pub async fn run(
        self,
        job_tx: mpsc::Sender<JobTemplate>,
        share_rx: mpsc::Receiver<ValidShare>,
        status_tx: mpsc::Sender<StratumStatus>,
    ) {
        match self.protocol_mode {
            ProtocolMode::V1Only => {
                info!(
                    pool = %self.config.pool1.url,
                    "Starting Stratum V1 client"
                );
                let client = StratumV1Client::new(self.config, job_tx, share_rx, status_tx);
                let client = if let Some(rx) = self.capacity_rx {
                    client.with_capacity_rx(rx)
                } else {
                    client
                };
                client.run().await;
            }

            #[cfg(feature = "sv2")]
            ProtocolMode::V2Only => {
                // Fail-closed: do not silently speak V1, and do not ignore a
                // missing/V1-incompatible backup. Auto mode (below) may still
                // fall back to V1.
                if let Err(reason) = validate_v2_only_contract(&self.config) {
                    error!(
                        reason = %reason,
                        "V2Only configuration refused (fail-closed); not falling back to Stratum V1"
                    );
                    let _ = status_tx
                        .send(StratumStatus::StateChanged(StratumState::Disconnected))
                        .await;
                    return;
                }
                let sv2_url = self
                    .config
                    .pool1
                    .sv2_url
                    .as_deref()
                    .unwrap_or(&self.config.pool1.url);
                let prefer_extended = Self::sv2_should_prefer_extended_channel(&self.config);
                // W1.4: mask wallet-shaped worker.
                info!(
                    sv2_url = %sv2_url,
                    nominal_hashrate_ghs = self.config.nominal_hashrate_ghs,
                    sv2_extended_channel = self.config.sv2_extended_channel,
                    prefer_extended_channel = prefer_extended,
                    worker = %dcentrald_common::wallet_mask::mask_wallet(&self.config.pool1.worker),
                    "Starting Stratum V2 client (encrypted, Noise_NX)"
                );
                let client = StratumV2Client::new(
                    self.config.clone(),
                    self.config.nominal_hashrate_ghs,
                    job_tx,
                    share_rx,
                    status_tx,
                );
                let client = if let Some(rx) = self.capacity_rx {
                    client.with_capacity_rx(rx)
                } else {
                    client
                };
                #[cfg(feature = "jd")]
                let client = if let Some(rx) = self.jd_status_rx {
                    client.with_job_declaration_status_rx(rx)
                } else {
                    client
                };
                client.run().await;
            }

            #[cfg(feature = "sv2")]
            ProtocolMode::Auto => {
                // Auto mode resolves against the active pool endpoint first.
                // This keeps old configs working while letting pool-specific
                // protocol hints override the global Auto mode.
                match self.protocol_mode_for_pool(&self.config.pool1) {
                    ProtocolMode::V2Only => {
                        if let Some(reason) = Self::sv2_standard_channel_block_reason(&self.config)
                        {
                            warn!(
                                nominal_hashrate_ghs = self.config.nominal_hashrate_ghs,
                                reason, "Auto mode: SV2 Standard channel refused; using Stratum V1"
                            );
                            let client =
                                StratumV1Client::new(self.config, job_tx, share_rx, status_tx);
                            let client = if let Some(rx) = self.capacity_rx {
                                client.with_capacity_rx(rx)
                            } else {
                                client
                            };
                            client.run().await;
                            return;
                        }
                        let sv2_url = self
                            .config
                            .pool1
                            .sv2_url
                            .as_deref()
                            .unwrap_or(&self.config.pool1.url);
                        let prefer_extended =
                            Self::sv2_should_prefer_extended_channel(&self.config);
                        info!(
                            sv2_url = %sv2_url,
                            v1_url = %self.config.pool1.url,
                            pool_protocol = ?self.config.pool1.protocol,
                            nominal_hashrate_ghs = self.config.nominal_hashrate_ghs,
                            sv2_extended_channel = self.config.sv2_extended_channel,
                            prefer_extended_channel = prefer_extended,
                            "Auto mode: active pool resolves to Stratum V2"
                        );

                        let client = StratumV2Client::new(
                            self.config.clone(),
                            self.config.nominal_hashrate_ghs,
                            job_tx,
                            share_rx,
                            status_tx,
                        );
                        let client = if let Some(rx) = self.capacity_rx {
                            client.with_capacity_rx(rx)
                        } else {
                            client
                        };
                        #[cfg(feature = "jd")]
                        let client = if let Some(rx) = self.jd_status_rx {
                            client.with_job_declaration_status_rx(rx)
                        } else {
                            client
                        };
                        client.run_auto_with_v1_fallback().await;
                    }
                    ProtocolMode::V1Only | ProtocolMode::Auto => {
                        info!(
                            pool = %self.config.pool1.url,
                            pool_protocol = ?self.config.pool1.protocol,
                            "Auto mode: active pool resolves to Stratum V1"
                        );
                        let client = StratumV1Client::new(self.config, job_tx, share_rx, status_tx);
                        let client = if let Some(rx) = self.capacity_rx {
                            client.with_capacity_rx(rx)
                        } else {
                            client
                        };
                        client.run().await;
                    }
                }
            }

            // V2Only must not silently speak V1 when SV2 is not compiled in.
            #[cfg(not(feature = "sv2"))]
            ProtocolMode::V2Only => {
                error!(
                    "protocol=sv2/v2 (V2Only) refused: SV2 is not compiled in (feature 'sv2' disabled); \
                     will not silently speak Stratum V1"
                );
                let _ = status_tx
                    .send(StratumStatus::StateChanged(StratumState::Disconnected))
                    .await;
            }

            // Auto may still fall back to V1 when the sv2 feature is absent.
            #[cfg(not(feature = "sv2"))]
            ProtocolMode::Auto => {
                warn!(
                    "SV2 requested but not compiled in (feature 'sv2' disabled), falling back to V1"
                );
                let client = StratumV1Client::new(self.config, job_tx, share_rx, status_tx);
                let client = if let Some(rx) = self.capacity_rx {
                    client.with_capacity_rx(rx)
                } else {
                    client
                };
                client.run().await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DonationConfig, PoolConfig};

    fn make_test_config() -> StratumConfig {
        StratumConfig {
            v1_policy: Default::default(),
            pool1: PoolConfig {
                url: "stratum+tcp://pool.example.com:3333".into(),
                worker: "test.worker".into(),
                password: "x".into(),
                sv2_url: None,
                protocol: None,
                split_bps: None,
            },
            pool2: None,
            pool3: None,
            routing_mode: "failover".into(),
            split_cycle_duration_s: 1800,
            primary_return_stability_secs: 900,
            no_notify_failover_secs: 300,
            reject_rate_failover_pct: 0,
            reject_rate_failover_min_samples: 100,
            smart_failover_enabled: false,
            smart_failover_drive: false,
            sv2_max_inbound_frame_bytes: 1_048_576,
            v1_max_inbound_line_bytes: 65_536,
            donation: DonationConfig::default(),
            version_rolling: true,
            version_rolling_mask: crate::types::default_version_rolling_mask(),
            suggest_difficulty: Some(256),
            hash_on_disconnect: true,
            nominal_hashrate_ghs: 13500.0,
            sv2_extended_channel: false,
            protocol: None,
        }
    }

    #[test]
    fn test_default_protocol_is_auto() {
        // W5.3: configs that omit `protocol` now default to Auto. Auto only
        // flips to V2 when the active pool advertises an SV2 endpoint, so
        // legacy V1-only operators keep mining over V1 unchanged. This
        // pin replaces the previous V1Only default contract.
        let config = make_test_config();
        let router = StratumRouter::new(config);
        assert_eq!(*router.protocol_mode(), ProtocolMode::Auto);
    }

    #[test]
    fn test_unknown_protocol_falls_back_to_auto_default() {
        // W5.3: an unrecognized protocol string must fall back to the new
        // Auto default — not silently get pinned to V1Only — so a typo
        // doesn't accidentally pin SV2-capable operators to V1.
        let mut config = make_test_config();
        config.protocol = Some("garbage-2".into());
        let router = StratumRouter::new(config);
        assert_eq!(*router.protocol_mode(), ProtocolMode::Auto);
    }

    #[test]
    fn test_explicit_v1_still_pins_v1only_after_default_flip() {
        // Operators who explicitly opted into "v1" or "sv1" must still get
        // V1Only after the W5.3 default flip — only the silent default
        // changes, not the explicit-pin contract.
        for alias in ["v1", "sv1"] {
            let mut config = make_test_config();
            config.protocol = Some(alias.into());
            let router = StratumRouter::new(config);
            assert_eq!(
                *router.protocol_mode(),
                ProtocolMode::V1Only,
                "explicit alias {alias} must still pin V1Only"
            );
        }
    }

    #[test]
    fn sv2_should_prefer_extended_channel_at_5_ths() {
        let mut config = make_test_config();
        // Below threshold: prefer Standard (assuming the standard-block gate
        // also passes — separate concern).
        config.nominal_hashrate_ghs = 4_999.0;
        assert!(!StratumRouter::sv2_should_prefer_extended_channel(&config));
        // At threshold: prefer Extended.
        config.nominal_hashrate_ghs = 5_000.0;
        assert!(StratumRouter::sv2_should_prefer_extended_channel(&config));
        // Multi-TH/s S9-class: prefer Extended.
        config.nominal_hashrate_ghs = 13_500.0;
        assert!(StratumRouter::sv2_should_prefer_extended_channel(&config));
    }

    #[test]
    fn sv2_extended_preference_is_independent_of_extended_channel_flag() {
        // The "should prefer" hint is informational and keys off hashrate.
        // The actual `sv2_extended_channel` config flag is a separate switch
        // (the consumer of the hint) — pin that the hint does not depend on
        // it so callers can use the hint to decide whether to flip the flag.
        let mut config = make_test_config();
        config.nominal_hashrate_ghs = 13_500.0;
        config.sv2_extended_channel = false;
        assert!(StratumRouter::sv2_should_prefer_extended_channel(&config));
        config.sv2_extended_channel = true;
        assert!(StratumRouter::sv2_should_prefer_extended_channel(&config));
    }

    #[test]
    fn test_explicit_sv1_protocol() {
        let mut config = make_test_config();
        config.protocol = Some("sv1".into());
        let router = StratumRouter::new(config);
        assert_eq!(*router.protocol_mode(), ProtocolMode::V1Only);
    }

    #[test]
    fn test_explicit_v1_protocol() {
        let mut config = make_test_config();
        config.protocol = Some("v1".into());
        let router = StratumRouter::new(config);
        assert_eq!(*router.protocol_mode(), ProtocolMode::V1Only);
    }

    #[test]
    fn test_sv2_protocol() {
        let mut config = make_test_config();
        config.protocol = Some("sv2".into());
        let router = StratumRouter::new(config);
        assert_eq!(*router.protocol_mode(), ProtocolMode::V2Only);
    }

    #[test]
    fn sv2_standard_channel_blocked_for_multi_ths_hashrate() {
        let mut config = make_test_config();
        config.nominal_hashrate_ghs = 13_500.0;
        config.sv2_extended_channel = false;

        assert!(StratumRouter::sv2_standard_channel_block_reason(&config).is_some());
    }

    #[test]
    fn sv2_standard_channel_allowed_below_one_ths() {
        let mut config = make_test_config();
        config.nominal_hashrate_ghs = 500.0;
        config.sv2_extended_channel = false;

        assert!(StratumRouter::sv2_standard_channel_block_reason(&config).is_none());
    }

    #[test]
    fn sv2_extended_channel_allows_multi_ths_hashrate() {
        let mut config = make_test_config();
        config.nominal_hashrate_ghs = 13_500.0;
        config.sv2_extended_channel = true;

        assert!(StratumRouter::sv2_standard_channel_block_reason(&config).is_none());
    }

    #[test]
    fn test_v2_protocol() {
        let mut config = make_test_config();
        config.protocol = Some("v2".into());
        let router = StratumRouter::new(config);
        assert_eq!(*router.protocol_mode(), ProtocolMode::V2Only);
    }

    #[test]
    fn test_auto_protocol() {
        let mut config = make_test_config();
        config.protocol = Some("auto".into());
        let router = StratumRouter::new(config);
        assert_eq!(*router.protocol_mode(), ProtocolMode::Auto);
    }

    #[test]
    fn test_unknown_protocol_defaults_to_auto() {
        // W5.3 default flip: unknown protocol values now resolve to Auto
        // (was V1Only). See test_unknown_protocol_falls_back_to_auto_default
        // above for the duplicated coverage that pins the contract change.
        let mut config = make_test_config();
        config.protocol = Some("garbage".into());
        let router = StratumRouter::new(config);
        assert_eq!(*router.protocol_mode(), ProtocolMode::Auto);
    }

    #[test]
    fn test_display_impl() {
        assert_eq!(format!("{}", ProtocolMode::V1Only), "v1");
        assert_eq!(format!("{}", ProtocolMode::V2Only), "v2");
        assert_eq!(format!("{}", ProtocolMode::Auto), "auto");
    }

    #[test]
    fn test_auto_uses_pool_sv2_url_when_pool_protocol_absent() {
        let mut config = make_test_config();
        config.protocol = Some("auto".into());
        config.pool1.sv2_url = Some("stratum2+tcp://v2.pool.example.com:3336".into());
        let router = StratumRouter::new(config);
        assert_eq!(
            router.protocol_mode_for_pool(&router.config.pool1),
            ProtocolMode::V2Only
        );
    }

    #[test]
    fn test_auto_respects_pool_level_sv1_override() {
        let mut config = make_test_config();
        config.protocol = Some("auto".into());
        config.pool1.sv2_url = Some("stratum2+tcp://v2.pool.example.com:3336".into());
        config.pool1.protocol = Some("sv1".into());
        let router = StratumRouter::new(config);
        assert_eq!(
            router.protocol_mode_for_pool(&router.config.pool1),
            ProtocolMode::V1Only
        );
    }

    #[test]
    fn test_auto_respects_pool_level_sv2_override() {
        let mut config = make_test_config();
        config.protocol = Some("auto".into());
        config.pool1.protocol = Some("sv2".into());
        let router = StratumRouter::new(config);
        assert_eq!(
            router.protocol_mode_for_pool(&router.config.pool1),
            ProtocolMode::V2Only
        );
    }

    // -----------------------------------------------------------------------
    // Pool-level Auto resolution + protocol-mode parser edge cases.
    //
    // Existing tests cover the global protocol mode + a handful of pool
    // override combinations, but several boundary cases are unpinned —
    // particularly the "pool-level auto" + sv2_url interaction, the
    // global-V2-with-pool-V1-override path, and the parser's
    // case-sensitivity behavior.
    // -----------------------------------------------------------------------

    #[test]
    fn test_pool_level_auto_with_sv2_url_resolves_to_v2() {
        let mut config = make_test_config();
        config.protocol = Some("v1".into()); // global = V1
        config.pool1.protocol = Some("auto".into()); // pool = auto
        config.pool1.sv2_url = Some("stratum2+tcp://v2.pool.example.com:3336".into());
        let router = StratumRouter::new(config);
        // Pool-level "auto" with sv2_url present beats global V1.
        assert_eq!(
            router.protocol_mode_for_pool(&router.config.pool1),
            ProtocolMode::V2Only
        );
    }

    #[test]
    fn test_pool_level_auto_without_sv2_url_resolves_to_v1() {
        let mut config = make_test_config();
        config.protocol = Some("v2".into()); // global = V2
        config.pool1.protocol = Some("auto".into()); // pool = auto
        config.pool1.sv2_url = None;
        let router = StratumRouter::new(config);
        // Pool-level "auto" without sv2_url falls back to V1, even when
        // the global mode is V2. Pool's auto resolution wins.
        assert_eq!(
            router.protocol_mode_for_pool(&router.config.pool1),
            ProtocolMode::V1Only
        );
    }

    #[test]
    fn test_global_v2_with_pool_level_v1_override_uses_v1() {
        // Pool-level explicit override beats global V2.
        let mut config = make_test_config();
        config.protocol = Some("v2".into());
        config.pool1.protocol = Some("v1".into());
        let router = StratumRouter::new(config);
        assert_eq!(
            router.protocol_mode_for_pool(&router.config.pool1),
            ProtocolMode::V1Only
        );
    }

    #[test]
    fn test_global_v1_with_pool_level_v2_override_uses_v2() {
        // Symmetric: pool-level V2 override beats global V1.
        let mut config = make_test_config();
        config.protocol = Some("v1".into());
        config.pool1.protocol = Some("v2".into());
        let router = StratumRouter::new(config);
        assert_eq!(
            router.protocol_mode_for_pool(&router.config.pool1),
            ProtocolMode::V2Only
        );
    }

    #[test]
    fn test_garbage_pool_protocol_falls_back_to_global_mode() {
        // Pool ships a misspelled protocol — the parser returns None and
        // resolution falls back to the global protocol mode.
        let mut config = make_test_config();
        config.protocol = Some("v2".into());
        config.pool1.protocol = Some("not-a-protocol".into());
        let router = StratumRouter::new(config);
        assert_eq!(
            router.protocol_mode_for_pool(&router.config.pool1),
            ProtocolMode::V2Only
        );
    }

    #[test]
    fn test_global_auto_without_pool_sv2_url_resolves_to_v1() {
        // Global "auto", no pool override, no sv2_url → V1.
        let mut config = make_test_config();
        config.protocol = Some("auto".into());
        config.pool1.sv2_url = None;
        let router = StratumRouter::new(config);
        assert_eq!(
            router.protocol_mode_for_pool(&router.config.pool1),
            ProtocolMode::V1Only
        );
    }

    #[test]
    fn parse_protocol_mode_accepts_all_aliases() {
        assert_eq!(
            StratumRouter::parse_protocol_mode(Some("sv1")),
            Some(ProtocolMode::V1Only)
        );
        assert_eq!(
            StratumRouter::parse_protocol_mode(Some("v1")),
            Some(ProtocolMode::V1Only)
        );
        assert_eq!(
            StratumRouter::parse_protocol_mode(Some("sv2")),
            Some(ProtocolMode::V2Only)
        );
        assert_eq!(
            StratumRouter::parse_protocol_mode(Some("v2")),
            Some(ProtocolMode::V2Only)
        );
        assert_eq!(
            StratumRouter::parse_protocol_mode(Some("auto")),
            Some(ProtocolMode::Auto)
        );
    }

    #[test]
    fn parse_protocol_mode_rejects_none_and_unknown() {
        // None must produce None so the caller's `.unwrap_or(V1Only)`
        // applies (backward-compat default).
        assert_eq!(StratumRouter::parse_protocol_mode(None), None);
        assert_eq!(StratumRouter::parse_protocol_mode(Some("")), None);
        assert_eq!(StratumRouter::parse_protocol_mode(Some("garbage")), None);
        assert_eq!(StratumRouter::parse_protocol_mode(Some("v3")), None);
    }

    #[test]
    fn parse_protocol_mode_is_case_sensitive() {
        // Pin the case-sensitivity contract: uppercase variants must NOT
        // match. A refactor that added case-insensitive matching would
        // be caught here so the protocol-string contract stays explicit.
        assert_eq!(StratumRouter::parse_protocol_mode(Some("SV1")), None);
        assert_eq!(StratumRouter::parse_protocol_mode(Some("V1")), None);
        assert_eq!(StratumRouter::parse_protocol_mode(Some("Sv2")), None);
        assert_eq!(StratumRouter::parse_protocol_mode(Some("AUTO")), None);
        assert_eq!(StratumRouter::parse_protocol_mode(Some("Auto")), None);
    }

    #[test]
    fn parse_protocol_mode_does_not_trim_whitespace() {
        // Whitespace around a valid mode is NOT trimmed. Pin so a refactor
        // that added trim() would change the behavior — operators relying
        // on strict-match config validation expect this.
        assert_eq!(StratumRouter::parse_protocol_mode(Some(" v1")), None);
        assert_eq!(StratumRouter::parse_protocol_mode(Some("v1 ")), None);
        assert_eq!(StratumRouter::parse_protocol_mode(Some(" sv2 ")), None);
    }

    #[test]
    fn protocol_mode_display_strings_match_config_aliases() {
        // The Display impl produces strings that round-trip through
        // parse_protocol_mode. Pin so a refactor of either side stays
        // self-consistent.
        for mode in [
            ProtocolMode::V1Only,
            ProtocolMode::V2Only,
            ProtocolMode::Auto,
        ] {
            let s = format!("{}", mode);
            let recovered = StratumRouter::parse_protocol_mode(Some(&s));
            assert_eq!(
                recovered.as_ref(),
                Some(&mode),
                "Display(\"{s}\") must round-trip through parse_protocol_mode"
            );
        }
    }

    fn v2_capable_backup(url: &str) -> PoolConfig {
        PoolConfig {
            url: url.into(),
            worker: "backup.worker".into(),
            password: "x".into(),
            sv2_url: Some("stratum2+tcp://v2.backup.example.com:3336".into()),
            protocol: Some("sv2".into()),
            split_bps: None,
        }
    }

    fn v1_backup(url: &str) -> PoolConfig {
        PoolConfig {
            url: url.into(),
            worker: "backup.worker".into(),
            password: "x".into(),
            sv2_url: None,
            protocol: Some("sv1".into()),
            split_bps: None,
        }
    }

    #[test]
    fn v2_only_without_backup_is_ok_when_standard_channel_is_safe() {
        let mut config = make_test_config();
        config.protocol = Some("sv2".into());
        config.nominal_hashrate_ghs = 500.0;
        config.sv2_extended_channel = false;
        let result = validate_v2_only_contract(&config);
        #[cfg(feature = "sv2")]
        result.expect("single-pool V2Only below 1 TH/s must be accepted");
        #[cfg(not(feature = "sv2"))]
        {
            let err = result.expect_err("V2Only must fail closed when SV2 is not compiled");
            assert!(err.contains("feature 'sv2' disabled"));
            assert!(err.contains("will not silently speak Stratum V1"));
        }
    }

    #[test]
    fn v2_only_refuses_silent_v1_fallback_on_standard_channel_block() {
        let mut config = make_test_config();
        config.protocol = Some("sv2".into());
        config.nominal_hashrate_ghs = 13_500.0;
        config.sv2_extended_channel = false;
        let err = validate_v2_only_contract(&config)
            .expect_err("V2Only must not silently fall back to V1 when Standard is unsafe");
        #[cfg(feature = "sv2")]
        {
            assert!(err.contains("will not silently fall back"));
            assert!(err.contains("V2Only"));
        }
        #[cfg(not(feature = "sv2"))]
        {
            assert!(err.contains("feature 'sv2' disabled"));
            assert!(err.contains("will not silently speak Stratum V1"));
        }
    }

    #[test]
    fn v2_only_refuses_missing_or_v1_incompatible_backup() {
        let mut config = make_test_config();
        config.protocol = Some("v2".into());
        config.nominal_hashrate_ghs = 500.0;
        config.pool2 = Some(v1_backup("stratum+tcp://backup.example.com:3333"));
        let err = validate_v2_only_contract(&config)
            .expect_err("V1 backup under V2Only must fail closed");
        #[cfg(feature = "sv2")]
        {
            assert!(err.contains("V1-incompatible") || err.contains("missing an SV2 endpoint"));
            assert!(err.contains("will not silently use Stratum V1"));
        }
        #[cfg(not(feature = "sv2"))]
        {
            assert!(err.contains("feature 'sv2' disabled"));
            assert!(err.contains("will not silently speak Stratum V1"));
        }
    }

    #[test]
    fn v2_only_refuses_sv2_backup_because_single_pool() {
        let mut config = make_test_config();
        config.protocol = Some("sv2".into());
        config.nominal_hashrate_ghs = 500.0;
        config.sv2_extended_channel = true;
        config.pool2 = Some(v2_capable_backup(
            "stratum2+tcp://v2.backup.example.com:3336",
        ));
        let err = validate_v2_only_contract(&config)
            .expect_err("even SV2-capable backups are unused on V2Only");
        #[cfg(feature = "sv2")]
        {
            assert!(err.contains("single-pool"));
            assert!(err.contains("BENCH_HOLD"));
        }
        #[cfg(not(feature = "sv2"))]
        {
            assert!(err.contains("feature 'sv2' disabled"));
            assert!(err.contains("will not silently speak Stratum V1"));
        }
    }

    #[test]
    fn v1_and_auto_may_keep_v1_backups() {
        let mut config = make_test_config();
        config.protocol = Some("sv1".into());
        config.pool2 = Some(v1_backup("stratum+tcp://backup.example.com:3333"));
        validate_v2_only_contract(&config).expect("V1Only backups are V1 failover, not V2Only");

        config.protocol = Some("auto".into());
        validate_v2_only_contract(&config).expect("Auto may use V1 backups");
        v2_only_backup_refusal(Some("auto"), &[("pool.failover1", Some("sv1"), None)])
            .expect("Auto backup check is a no-op");
    }

    #[test]
    fn v2_only_backup_refusal_names_missing_sv2_url() {
        let err = v2_only_backup_refusal(Some("sv2"), &[("pool.failover1", None, None)])
            .expect_err("configured backup with no sv2_url is missing/V1");
        assert!(err.contains("pool.failover1"));
        assert!(err.contains("missing an SV2 endpoint") || err.contains("V1-incompatible"));
    }

    #[test]
    fn endpoint_sv2_capable_requires_sv2_url_or_protocol() {
        assert!(!endpoint_is_sv2_capable(None, None));
        assert!(!endpoint_is_sv2_capable(Some("sv1"), None));
        assert!(!endpoint_is_sv2_capable(Some("v1"), Some("")));
        assert!(endpoint_is_sv2_capable(Some("sv2"), None));
        assert!(endpoint_is_sv2_capable(
            None,
            Some("stratum2+tcp://v2.example:3336")
        ));
    }

    #[test]
    fn v2_only_refuses_datum_protocol() {
        let mut config = make_test_config();
        config.protocol = Some("datum".into());
        let err = validate_v2_only_contract(&config).expect_err("DATUM is not implemented");
        assert!(err.contains("DATUM"));
        assert!(err.contains("not implemented"));
    }
}
