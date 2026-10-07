use serde::{Deserialize, Serialize};

pub const UPDATE_SCHEMA_VERSION: u8 = 1;

pub const CHANNEL_FEED_PROFILE: &str = "dcentos.signed-channel-feed/v1";
pub const CHANNEL_FEED_SCHEMA: u8 = 1;
pub const MAX_CHANNEL_FEED_BYTES: usize = 1024 * 1024;
pub const MAX_CHANNEL_FEED_TARGETS: usize = 256;

/// Ed25519 signature over the exact UTF-8 bytes of `payload`.
///
/// Keeping the signed document as a string avoids cross-language JSON
/// reserialization differences. Consumers must verify with their independently
/// trusted release key before deserializing the payload as ChannelFeedPayload.
/// This wire type alone grants no download or installation authority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelFeed {
    pub profile: String,
    pub payload: String,
    /// Exactly 128 lowercase hex characters: the 64-byte Ed25519 signature.
    pub signature: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UpdateChannel {
    Beta,
    Stable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChannelArtifactKind {
    #[serde(rename = "sysupgrade-tar")]
    SysupgradeTar,
    #[serde(rename = "native-sd-image")]
    NativeSdImage,
    #[serde(rename = "sd-payload-tar")]
    SdPayloadTar,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChannelInstallRoute {
    FirstInstallAndSelfUpdate,
    SelfUpdateOnly,
    SdTrialBootOnly,
    OperatorStaged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelFeedPayload {
    pub schema: u8,
    pub product: String,
    pub release_channel: UpdateChannel,
    pub source_commit: String,
    pub targets: Vec<ChannelFeedTarget>,
}

/// One exact board's published primary artifact. Local runtime policy and
/// verified package authority must independently permit an in-device update.
/// A signed SD-only or operator-staged row never acquires that permission.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelFeedTarget {
    pub board_target: String,
    pub version: String,
    pub minimum_version: String,
    pub release_channel: UpdateChannel,
    pub artifact_kind: ChannelArtifactKind,
    pub install_route: ChannelInstallRoute,
    pub hardware_recipe: String,
    pub sha256: String,
    pub url: String,
    pub size: u64,
}

/// Host Toolbox discovery uses the same signed-byte ChannelFeed envelope.
/// These types are separate from firmware targets and grant no install authority.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ToolboxFeedProduct {
    #[serde(rename = "DCENT_TOOLBOX")]
    Toolbox,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ToolboxPlatformTarget {
    #[serde(rename = "windows-x86_64")]
    WindowsX86_64,
    #[serde(rename = "macos-x86_64")]
    MacosX86_64,
    #[serde(rename = "macos-arm64")]
    MacosArm64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ToolboxArtifactKind {
    #[serde(rename = "windows-installer")]
    WindowsInstaller,
    #[serde(rename = "macos-pkg")]
    MacosPkg,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolboxChannelFeedPayload {
    pub schema: u8,
    pub product: ToolboxFeedProduct,
    pub release_channel: UpdateChannel,
    pub source_commit: String,
    pub targets: Vec<ToolboxChannelFeedTarget>,
}

/// Consumers must join artifact kind to the exact process platform, validate
/// bounded HTTPS/size/digest/semver fields and authenticate before selection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolboxChannelFeedTarget {
    pub platform_target: ToolboxPlatformTarget,
    pub version: String,
    pub minimum_version: String,
    pub release_channel: UpdateChannel,
    pub artifact_kind: ToolboxArtifactKind,
    pub sha256: String,
    pub url: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InstallIntent {
    pub schema_version: u8,
    pub installer: String,
    pub install_origin: String,
    pub bootstrap_transport: String,
    pub install_method: String,
    pub hardening_profile: String,
    pub target_ip: Option<String>,
    pub model: Option<String>,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub hwid: Option<String>,
    pub package_version: Option<String>,
    pub package_model: Option<String>,
    pub board_target: Option<String>,
    pub package_type: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PackagePayload {
    pub name: String,
    pub path: String,
    pub size: Option<u64>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ToolboxPackageInfo {
    pub install_command: String,
    pub update_command: String,
    pub upload_endpoint: Option<String>,
    pub board_target_header: Option<String>,
    pub device_model_header: Option<String>,
    pub requires_inactive_slot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PackageManifest {
    pub schema: u8,
    pub product: String,
    pub family: String,
    pub package_type: String,
    pub board_target: String,
    pub device_model: Option<String>,
    pub version: Option<String>,
    pub created_at_utc: String,
    #[serde(default)]
    pub signature_algorithm: Option<String>,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub ota_signature_algorithm: Option<String>,
    #[serde(default)]
    pub ota_key_id: Option<String>,
    #[serde(default)]
    pub ota_signature: Option<String>,
    pub payloads: Vec<PackagePayload>,
    pub toolbox: ToolboxPackageInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMetadata {
    pub schema: u8,
    pub product: String,
    pub family: String,
    pub device_model: String,
    pub board_target: String,
    pub current_version: String,
    pub package_type: String,
    pub upload_endpoint: Option<String>,
    pub board_target_header: Option<String>,
    pub device_model_header: Option<String>,
    pub inactive_slot_supported: bool,
    #[serde(default)]
    pub signature_capable: bool,
    #[serde(default)]
    pub signature_required: bool,
    #[serde(default)]
    pub allow_unsigned: bool,
    #[serde(default)]
    pub key_id: Option<String>,
    pub install_intent: Option<InstallIntent>,
    pub toolbox: ToolboxPackageInfo,
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHANNEL_FIXTURE: &str = include_str!("../tests/fixtures/channel_feed.json");

    #[test]
    fn signed_channel_fixture_preserves_exact_payload_and_separate_install_routes() {
        let feed: ChannelFeed = serde_json::from_str(CHANNEL_FIXTURE).unwrap();
        assert_eq!(feed.profile, CHANNEL_FEED_PROFILE);
        assert_eq!(feed.signature.len(), 128);
        assert!(feed.payload.ends_with('\n'));
        let encoded = serde_json::to_vec(&feed).unwrap();
        let recovered: ChannelFeed = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(recovered.payload.as_bytes(), feed.payload.as_bytes());
        let payload: ChannelFeedPayload = serde_json::from_str(&feed.payload).unwrap();
        assert_eq!(payload.schema, CHANNEL_FEED_SCHEMA);
        assert_eq!(payload.release_channel, UpdateChannel::Beta);
        assert_eq!(payload.targets[0].board_target, "am1-s9");
        assert_eq!(payload.targets[0].minimum_version, "0.9.0");
        assert_eq!(
            payload.targets[0].artifact_kind,
            ChannelArtifactKind::SysupgradeTar
        );
        assert_eq!(
            payload.targets[0].install_route,
            ChannelInstallRoute::FirstInstallAndSelfUpdate
        );
        assert_eq!(
            payload.targets[1].artifact_kind,
            ChannelArtifactKind::NativeSdImage
        );
        assert_eq!(
            payload.targets[1].install_route,
            ChannelInstallRoute::SdTrialBootOnly
        );
        assert_eq!(payload.targets[1].size, 2_147_483_648);
    }

    #[test]
    fn channel_wire_refuses_duplicate_unknown_missing_or_coerced_authority_fields() {
        let feed: ChannelFeed = serde_json::from_str(CHANNEL_FIXTURE).unwrap();
        let original: serde_json::Value = serde_json::from_str(&feed.payload).unwrap();
        for (field, value) in [
            ("release_channel", serde_json::json!("lab")),
            ("artifact_kind", serde_json::json!("unknown")),
            ("install_route", serde_json::json!("automatic")),
            ("size", serde_json::json!(-1)),
            ("size", serde_json::json!("1048576")),
            ("size", serde_json::json!(1048576.5)),
            ("minimum_version", serde_json::Value::Null),
            ("unsigned_allowed", serde_json::json!(true)),
        ] {
            let mut changed = original.clone();
            changed["targets"][0][field] = value;
            assert!(
                serde_json::from_value::<ChannelFeedPayload>(changed).is_err(),
                "{field}"
            );
        }
        for field in [
            "board_target",
            "minimum_version",
            "hardware_recipe",
            "sha256",
            "url",
            "size",
        ] {
            let mut changed = original.clone();
            changed["targets"][0].as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<ChannelFeedPayload>(changed).is_err(),
                "{field}"
            );
        }
        let duplicated = feed.payload.replace(
            "\"board_target\": \"am1-s9\"",
            "\"board_target\": \"am1-s9\", \"board_target\": \"am2-s17e\"",
        );
        assert_ne!(duplicated, feed.payload);
        assert!(serde_json::from_str::<ChannelFeedPayload>(&duplicated).is_err());
        let mut envelope: serde_json::Value = serde_json::from_str(CHANNEL_FIXTURE).unwrap();
        envelope["public_key"] = serde_json::json!("untrusted feed-selected key");
        assert!(serde_json::from_value::<ChannelFeed>(envelope).is_err());
    }

    #[test]
    fn schema_version_is_pinned() {
        // Update protocol version. Drift here means downstream installers
        // (toolbox, dcentaxe OTA) silently fail-closed.
        assert_eq!(UPDATE_SCHEMA_VERSION, 1);
    }

    fn sample_payload() -> PackagePayload {
        PackagePayload {
            name: "rootfs.ext2".to_string(),
            path: "/tmp/rootfs.ext2".to_string(),
            size: Some(25_621_540),
            sha256: Some(
                "c3e6eca12a8986864571429f42063baaeec33bbdf422c2538789c8c63d79183d".to_string(),
            ),
        }
    }

    fn sample_toolbox() -> ToolboxPackageInfo {
        ToolboxPackageInfo {
            install_command: "dcent install".to_string(),
            update_command: "dcent update".to_string(),
            upload_endpoint: Some("/api/upload".to_string()),
            board_target_header: Some("X-DCENT-Board-Target".to_string()),
            device_model_header: Some("X-DCENT-Device-Model".to_string()),
            requires_inactive_slot: true,
        }
    }

    fn sample_install_intent() -> InstallIntent {
        InstallIntent {
            schema_version: UPDATE_SCHEMA_VERSION,
            installer: "dcent-toolbox".to_string(),
            install_origin: "operator".to_string(),
            bootstrap_transport: "ssh".to_string(),
            install_method: "sysupgrade".to_string(),
            hardening_profile: "default".to_string(),
            target_ip: Some("203.0.113.39".to_string()),
            model: Some("S9".to_string()),
            hostname: Some("miner-39".to_string()),
            mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            hwid: Some("hw-39".to_string()),
            package_version: Some("0.5.0".to_string()),
            package_model: Some("S9".to_string()),
            board_target: Some("am1-s9".to_string()),
            package_type: Some("sysupgrade".to_string()),
            created_at: "2026-04-30T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn install_intent_round_trips_through_json() {
        let original = sample_install_intent();
        let json = serde_json::to_string(&original).unwrap();
        let recovered: InstallIntent = serde_json::from_str(&json).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn install_intent_serializes_in_camelcase_wire_form() {
        let json = serde_json::to_value(&sample_install_intent()).unwrap();
        // Pin every camelCase field so a refactor can't silently flip
        // any of them — every consumer relies on these names.
        for field in [
            "schemaVersion",
            "installer",
            "installOrigin",
            "bootstrapTransport",
            "installMethod",
            "hardeningProfile",
            "targetIp",
            "model",
            "hostname",
            "mac",
            "hwid",
            "packageVersion",
            "packageModel",
            "boardTarget",
            "packageType",
            "createdAt",
        ] {
            assert!(
                json.get(field).is_some(),
                "InstallIntent must expose {field} on the wire"
            );
        }

        // snake_case must NOT appear.
        for forbidden in [
            "schema_version",
            "install_origin",
            "bootstrap_transport",
            "install_method",
            "hardening_profile",
            "target_ip",
            "package_version",
            "package_model",
            "board_target",
            "package_type",
            "created_at",
        ] {
            assert!(
                json.get(forbidden).is_none(),
                "InstallIntent must NOT serialize {forbidden} (snake_case form)"
            );
        }
    }

    #[test]
    fn package_payload_carries_optional_size_and_sha256() {
        let original = sample_payload();
        let json = serde_json::to_string(&original).unwrap();
        let recovered: PackagePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(original, recovered);
        assert_eq!(recovered.size, Some(25_621_540));
        assert_eq!(
            recovered.sha256,
            Some("c3e6eca12a8986864571429f42063baaeec33bbdf422c2538789c8c63d79183d".to_string())
        );
    }

    #[test]
    fn package_payload_supports_missing_size_and_sha256() {
        let payload = PackagePayload {
            name: "stub".to_string(),
            path: "/dev/null".to_string(),
            size: None,
            sha256: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        let recovered: PackagePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(payload, recovered);
        assert!(recovered.size.is_none());
        assert!(recovered.sha256.is_none());
    }

    #[test]
    fn package_manifest_signature_fields_default_to_none() {
        // signature_algorithm/key_id/signature are #[serde(default)] so a
        // manifest emitted before signing was added must still parse.
        // Pin the legacy-compat path.
        let pre_signature = r#"{
            "schema": 1,
            "product": "dcentos",
            "family": "dcentos",
            "packageType": "sysupgrade",
            "boardTarget": "am1-s9",
            "deviceModel": "S9",
            "version": "0.5.0",
            "createdAtUtc": "2026-04-30T00:00:00Z",
            "payloads": [],
            "toolbox": {
                "installCommand": "dcent install",
                "updateCommand": "dcent update",
                "uploadEndpoint": null,
                "boardTargetHeader": null,
                "deviceModelHeader": null,
                "requiresInactiveSlot": false
            }
        }"#;
        let manifest: PackageManifest = serde_json::from_str(pre_signature).unwrap();
        assert!(manifest.signature_algorithm.is_none());
        assert!(manifest.key_id.is_none());
        assert!(manifest.signature.is_none());
        assert!(manifest.ota_signature_algorithm.is_none());
        assert!(manifest.ota_key_id.is_none());
        assert!(manifest.ota_signature.is_none());
    }

    #[test]
    fn package_manifest_round_trips_with_signature_fields() {
        let manifest = PackageManifest {
            schema: 1,
            product: "dcentos".to_string(),
            family: "dcentos".to_string(),
            package_type: "sysupgrade".to_string(),
            board_target: "am1-s9".to_string(),
            device_model: Some("S9".to_string()),
            version: Some("0.5.0".to_string()),
            created_at_utc: "2026-04-30T00:00:00Z".to_string(),
            signature_algorithm: Some("ed25519".to_string()),
            key_id: Some("dcent-2026-q1".to_string()),
            signature: Some("0xdeadbeef".to_string()),
            ota_signature_algorithm: Some("ed25519".to_string()),
            ota_key_id: Some("dcent-ota-2026".to_string()),
            ota_signature: Some("0xcafebabe".to_string()),
            payloads: vec![sample_payload()],
            toolbox: sample_toolbox(),
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let recovered: PackageManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, recovered);
    }

    #[test]
    fn update_metadata_signature_fields_default_to_safe_defaults() {
        // signature_capable, signature_required, allow_unsigned all
        // default to false. Pin so a refactor that defaulted
        // allow_unsigned=true would silently downgrade OTA security.
        let bare = r#"{
            "schema": 1,
            "product": "dcentos",
            "family": "dcentos",
            "deviceModel": "S9",
            "boardTarget": "am1-s9",
            "currentVersion": "0.5.0",
            "packageType": "sysupgrade",
            "uploadEndpoint": null,
            "boardTargetHeader": null,
            "deviceModelHeader": null,
            "inactiveSlotSupported": true,
            "installIntent": null,
            "toolbox": {
                "installCommand": "dcent install",
                "updateCommand": "dcent update",
                "uploadEndpoint": null,
                "boardTargetHeader": null,
                "deviceModelHeader": null,
                "requiresInactiveSlot": false
            }
        }"#;
        let metadata: UpdateMetadata = serde_json::from_str(bare).unwrap();

        // The defaults must match the safe direction:
        //   signature_capable: false  (cannot verify signatures yet)
        //   signature_required: false (operator hasn't enforced)
        //   allow_unsigned: false     (REJECT unsigned by default)
        // A flip to allow_unsigned=true default would silently weaken
        // the OTA security posture for every downstream installer.
        assert!(!metadata.signature_capable);
        assert!(!metadata.signature_required);
        assert!(!metadata.allow_unsigned);
        assert!(metadata.key_id.is_none());
    }

    #[test]
    fn update_metadata_round_trips_with_signature_state() {
        let metadata = UpdateMetadata {
            schema: 1,
            product: "dcentos".to_string(),
            family: "dcentos".to_string(),
            device_model: "S19".to_string(),
            board_target: "am2-s19".to_string(),
            current_version: "1.0.0".to_string(),
            package_type: "sysupgrade".to_string(),
            upload_endpoint: Some("/api/upload".to_string()),
            board_target_header: Some("X-DCENT-Board-Target".to_string()),
            device_model_header: Some("X-DCENT-Device-Model".to_string()),
            inactive_slot_supported: true,
            signature_capable: true,
            signature_required: true,
            allow_unsigned: false,
            key_id: Some("dcent-2026-q1".to_string()),
            install_intent: Some(sample_install_intent()),
            toolbox: sample_toolbox(),
        };
        let json = serde_json::to_string(&metadata).unwrap();
        let recovered: UpdateMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(metadata, recovered);
    }

    #[test]
    fn update_metadata_serializes_in_camelcase_wire_form() {
        let metadata = UpdateMetadata {
            schema: 1,
            product: "dcentos".to_string(),
            family: "dcentos".to_string(),
            device_model: "S9".to_string(),
            board_target: "am1-s9".to_string(),
            current_version: "0.5.0".to_string(),
            package_type: "sysupgrade".to_string(),
            upload_endpoint: None,
            board_target_header: None,
            device_model_header: None,
            inactive_slot_supported: true,
            signature_capable: false,
            signature_required: false,
            allow_unsigned: false,
            key_id: None,
            install_intent: None,
            toolbox: sample_toolbox(),
        };
        let json = serde_json::to_value(&metadata).unwrap();

        for field in [
            "schema",
            "product",
            "family",
            "deviceModel",
            "boardTarget",
            "currentVersion",
            "packageType",
            "uploadEndpoint",
            "boardTargetHeader",
            "deviceModelHeader",
            "inactiveSlotSupported",
            "signatureCapable",
            "signatureRequired",
            "allowUnsigned",
            "keyId",
            "installIntent",
            "toolbox",
        ] {
            assert!(
                json.get(field).is_some(),
                "UpdateMetadata must expose {field}"
            );
        }

        for forbidden in [
            "device_model",
            "board_target",
            "current_version",
            "package_type",
            "upload_endpoint",
            "board_target_header",
            "device_model_header",
            "inactive_slot_supported",
            "signature_capable",
            "signature_required",
            "allow_unsigned",
            "key_id",
            "install_intent",
        ] {
            assert!(
                json.get(forbidden).is_none(),
                "UpdateMetadata must NOT serialize {forbidden}"
            );
        }
    }
}
