//! Authenticated update discovery. Feed selection is not installation authority:
//! the downloaded package still needs the existing local policy and OTA checks.
use std::collections::BTreeSet;

use dcent_schema::update::{
    ChannelArtifactKind, ChannelFeed, ChannelFeedPayload, ChannelFeedTarget, ChannelInstallRoute,
    UpdateChannel, CHANNEL_FEED_PROFILE, CHANNEL_FEED_SCHEMA, MAX_CHANNEL_FEED_BYTES,
    MAX_CHANNEL_FEED_TARGETS,
};
use semver::Version;
use sha2::{Digest, Sha256};

const MAX_PUBLISHED_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub(crate) const MAX_REMOTE_UPDATE_BYTES: u64 = 512 * 1024 * 1024;

pub(crate) struct VerifiedChannelFeed {
    payload: ChannelFeedPayload,
    sha256: String,
}

impl VerifiedChannelFeed {
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(crate) fn select_update(
        &self,
        board: &str,
        current_version: &str,
        hardware_recipe: &str,
    ) -> Result<&ChannelFeedTarget, String> {
        let current = version(current_version)?;
        let target = self
            .payload
            .targets
            .iter()
            .find(|row| row.board_target == board)
            .ok_or("This channel has no release for the exact installed board.")?;
        if target.hardware_recipe != hardware_recipe {
            return Err("The release does not match the installed hardware recipe.".into());
        }
        if target.artifact_kind != ChannelArtifactKind::SysupgradeTar
            || !matches!(
                target.install_route,
                ChannelInstallRoute::FirstInstallAndSelfUpdate
                    | ChannelInstallRoute::SelfUpdateOnly
            )
        {
            return Err(
                "This release requires its external-media or operator install route.".into(),
            );
        }
        if target.size > MAX_REMOTE_UPDATE_BYTES {
            return Err("The release exceeds the in-device download size limit.".into());
        }
        if version(&target.minimum_version)?
            .cmp_precedence(&current)
            .is_gt()
        {
            return Err(
                "The installed version is older than this release's minimum update version.".into(),
            );
        }
        if !version(&target.version)?.cmp_precedence(&current).is_gt() {
            return Err("No newer release is available for this board.".into());
        }
        Ok(target)
    }
}

pub(crate) fn verify(raw: &[u8], channel: UpdateChannel) -> Result<VerifiedChannelFeed, String> {
    let key = crate::ota_signature::compiled_manifest_public_key_hex()
        .ok_or("This image has no trusted release key for channel updates.")?;
    verify_with_key(raw, channel, &decode_hex::<32>(key)?)
}

pub(crate) fn check_package_identity(
    authority: &crate::ota_signature::AuthorizedSysupgrade,
    target: &ChannelFeedTarget,
) -> Result<(), String> {
    if authority.board_target() != target.board_target || authority.version() != target.version {
        return Err(
            "Authenticated package target/version differs from the selected channel release".into(),
        );
    }
    Ok(())
}

fn verify_with_key(
    raw: &[u8],
    channel: UpdateChannel,
    key: &[u8; 32],
) -> Result<VerifiedChannelFeed, String> {
    if raw.is_empty() || raw.len() > MAX_CHANNEL_FEED_BYTES {
        return Err("Channel feed exceeds the input size limit.".into());
    }
    // Deserialize into strict structs directly: converting through Value would
    // discard duplicate fields before signature-authority validation.
    let envelope: ChannelFeed = serde_json::from_slice(raw)
        .map_err(|_| "Channel feed envelope is malformed or has unknown/duplicate fields.")?;
    if envelope.profile != CHANNEL_FEED_PROFILE || envelope.payload.is_empty() {
        return Err("Unsupported channel feed profile.".into());
    }
    let signature = decode_hex::<64>(&envelope.signature)?;
    crate::ota_signature::verify_manifest_signature_with_explicit_pubkey(
        envelope.payload.as_bytes(),
        &signature,
        key,
    )?;
    let payload: ChannelFeedPayload = serde_json::from_str(&envelope.payload)
        .map_err(|_| "Signed channel payload is malformed or has unknown/duplicate fields.")?;
    if payload.schema != CHANNEL_FEED_SCHEMA
        || payload.product != "DCENT_OS"
        || payload.release_channel != channel
        || payload.targets.is_empty()
        || payload.targets.len() > MAX_CHANNEL_FEED_TARGETS
    {
        return Err("Channel payload product, channel, schema or target count is invalid.".into());
    }
    if !matches!(payload.source_commit.len(), 40 | 64) || !lower_hex(&payload.source_commit) {
        return Err("Channel feed requires an exact source commit.".into());
    }
    let mut boards = BTreeSet::new();
    for target in &payload.targets {
        if !board_token(&target.board_target)
            || !boards.insert(&target.board_target)
            || target.release_channel != channel
        {
            return Err(
                "Channel feed contains a duplicate, malformed or foreign-channel board.".into(),
            );
        }
        if !matches!(
            target.hardware_recipe.as_str(),
            "board-default" | "am2-s19j-xil-loki"
        ) || (target.hardware_recipe == "am2-s19j-xil-loki"
            && target.board_target != "am2-s19j")
        {
            return Err("Channel feed hardware recipe is not bound to its exact board.".into());
        }
        if target.size == 0 || target.size > MAX_PUBLISHED_ARTIFACT_BYTES {
            return Err("Channel artifact size is outside the published artifact bound.".into());
        }
        decode_hex::<32>(&target.sha256)?;
        artifact_url(&target.url)?;
        if version(&target.minimum_version)?
            .cmp_precedence(&version(&target.version)?)
            .is_gt()
        {
            return Err("Channel release version is older than its minimum update version.".into());
        }
    }
    Ok(VerifiedChannelFeed {
        payload,
        sha256: format!("{:x}", Sha256::digest(raw)),
    })
}

#[cfg(test)]
pub(super) fn test_verify(
    raw: &[u8],
    channel: UpdateChannel,
    key: &[u8; 32],
) -> Result<VerifiedChannelFeed, String> {
    verify_with_key(raw, channel, key)
}

pub(crate) fn artifact_url(raw: &str) -> Result<reqwest::Url, String> {
    if raw.is_empty()
        || raw.len() > 2048
        || raw
            .bytes()
            .any(|byte| !byte.is_ascii() || byte <= b' ' || byte == 0x7f || byte == b'\\')
    {
        return Err("Release URL must be a bounded HTTPS URL without whitespace.".into());
    }
    let parsed = reqwest::Url::parse(raw).map_err(|_| "Release URL is malformed.")?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || parsed.query().is_some()
    {
        return Err("Release URL requires HTTPS without credentials, query or fragment.".into());
    }
    Ok(parsed)
}

fn version(raw: &str) -> Result<Version, String> {
    if raw.is_empty() || raw.len() > 128 {
        return Err("Release version exceeds the input bound.".into());
    }
    let value =
        Version::parse(raw).map_err(|_| "Release version must use semantic version syntax.")?;
    // Build metadata does not establish precedence and cannot create an update
    // from otherwise equal versions. Require the producer's canonical spelling.
    if value.to_string() != raw {
        return Err("Release version is not canonical.".into());
    }
    Ok(value)
}

fn board_token(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 96
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn lower_hex(raw: &str) -> bool {
    raw.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_hex<const N: usize>(raw: &str) -> Result<[u8; N], String> {
    if raw.len() != N * 2 || !lower_hex(raw) {
        return Err(
            "Channel signature, key or digest has an invalid lowercase hex encoding.".into(),
        );
    }
    let mut decoded = [0; N];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&raw[index * 2..index * 2 + 2], 16)
            .map_err(|_| "Invalid channel hex encoding.")?;
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const FIXTURE: &[u8] =
        include_bytes!("../../../../dcent-schema/tests/fixtures/channel_feed.json");
    const PUBLIC_KEY: &str =
        include_str!("../../../../dcent-schema/tests/fixtures/channel_feed_public_key.txt");

    fn fixture() -> VerifiedChannelFeed {
        verify_with_key(
            FIXTURE,
            UpdateChannel::Beta,
            &decode_hex(PUBLIC_KEY.trim()).unwrap(),
        )
        .unwrap()
    }

    fn signed_change(change: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let mut envelope: ChannelFeed = serde_json::from_slice(FIXTURE).unwrap();
        let mut payload: serde_json::Value = serde_json::from_str(&envelope.payload).unwrap();
        change(&mut payload);
        envelope.payload = serde_json::to_string(&payload).unwrap();
        envelope.signature = SigningKey::from_bytes(&[17; 32])
            .sign(envelope.payload.as_bytes())
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        serde_json::to_vec(&envelope).unwrap()
    }

    #[test]
    fn actual_signed_fixture_selects_exact_newer_update_but_never_sd_media() {
        let feed = fixture();
        assert_eq!(feed.sha256().len(), 64);
        assert_eq!(
            feed.select_update("am1-s9", "0.9.0", "board-default")
                .unwrap()
                .version,
            "0.10.0"
        );
        for (board, version, recipe) in [
            ("am1-s9i", "0.9.0", "board-default"),
            ("am1-s9", "0.8.0", "board-default"),
            ("am1-s9", "0.10.0", "board-default"),
            ("am1-s9", "1.0.0", "board-default"),
            ("am1-s9", "invalid", "board-default"),
            ("am1-s9", "0.9.0", "am2-s19j-xil-loki"),
            ("am2-s17e", "0.9.0", "board-default"),
        ] {
            assert!(feed.select_update(board, version, recipe).is_err());
        }
    }

    #[test]
    fn signature_channel_and_exact_payload_bytes_are_required() {
        let key = decode_hex(PUBLIC_KEY.trim()).unwrap();
        assert!(verify_with_key(FIXTURE, UpdateChannel::Stable, &key).is_err());
        assert!(verify_with_key(FIXTURE, UpdateChannel::Beta, &[5; 32]).is_err());
        let mut envelope: ChannelFeed = serde_json::from_slice(FIXTURE).unwrap();
        envelope.payload.push(' ');
        assert!(verify_with_key(
            &serde_json::to_vec(&envelope).unwrap(),
            UpdateChannel::Beta,
            &key
        )
        .is_err());
        assert!(verify_with_key(
            &vec![b' '; MAX_CHANNEL_FEED_BYTES + 1],
            UpdateChannel::Beta,
            &key
        )
        .is_err());
    }

    #[test]
    fn even_correctly_signed_invalid_metadata_is_refused() {
        let key = decode_hex(PUBLIC_KEY.trim()).unwrap();
        for (name, value) in [
            (
                "url",
                serde_json::json!("http://releases.example.invalid/a.tar"),
            ),
            (
                "url",
                serde_json::json!("https://user:password@example.invalid/a.tar"),
            ),
            (
                "url",
                serde_json::json!("https://example.invalid/a.tar#other"),
            ),
            ("sha256", serde_json::json!("A".repeat(64))),
            ("size", serde_json::json!(0)),
            ("version", serde_json::json!("newest")),
            ("minimum_version", serde_json::json!("1.0.0")),
            ("hardware_recipe", serde_json::json!("am2-s19j-xil-loki")),
        ] {
            let raw = signed_change(|payload| payload["targets"][0][name] = value);
            assert!(
                verify_with_key(&raw, UpdateChannel::Beta, &key).is_err(),
                "{name}"
            );
        }
        let duplicate = signed_change(|payload| {
            let target = payload["targets"][0].clone();
            payload["targets"].as_array_mut().unwrap().push(target);
        });
        assert!(verify_with_key(&duplicate, UpdateChannel::Beta, &key).is_err());
    }

    #[test]
    fn semantic_version_order_does_not_promote_prerelease_over_final() {
        assert!(version("0.10.0-beta.2").unwrap() < version("0.10.0").unwrap());
        assert!(version("v0.10.0").is_err());
        assert!(version("0.10.bad.0").is_err());
        let raw = signed_change(|payload| {
            payload["targets"][0]["version"] = serde_json::json!("0.10.0+build.2")
        });
        let feed = verify_with_key(
            &raw,
            UpdateChannel::Beta,
            &decode_hex(PUBLIC_KEY.trim()).unwrap(),
        )
        .unwrap();
        assert!(feed
            .select_update("am1-s9", "0.10.0+build.1", "board-default")
            .is_err());
    }
}
