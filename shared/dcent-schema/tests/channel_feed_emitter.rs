//! Cross-language wire contract: consume bytes from the production emitter.
use dcent_schema::update::{
    ChannelArtifactKind, ChannelFeed, ChannelFeedPayload, ChannelInstallRoute,
};

#[test]
fn actual_signed_release_emitter_conforms_to_channel_feed_schema() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../dcentos/scripts/test_release_channel_feed.py");
    let output = std::process::Command::new("python3")
        .arg(script)
        .arg("--schema-fixture")
        .output()
        .expect("offline Python/OpenSSL fixture tools");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: ChannelFeed = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope.profile, dcent_schema::update::CHANNEL_FEED_PROFILE);
    assert_eq!(envelope.signature.len(), 128);
    let payload: ChannelFeedPayload = serde_json::from_str(&envelope.payload).unwrap();
    assert_eq!(payload.schema, dcent_schema::update::CHANNEL_FEED_SCHEMA);
    let s9 = payload
        .targets
        .iter()
        .find(|row| row.board_target == "am1-s9")
        .unwrap();
    assert_eq!(s9.artifact_kind, ChannelArtifactKind::SysupgradeTar);
    assert_eq!(s9.minimum_version, "0.9.0");
    let sd = payload
        .targets
        .iter()
        .find(|row| row.board_target == "am2-s17e")
        .unwrap();
    assert_eq!(sd.artifact_kind, ChannelArtifactKind::NativeSdImage);
    assert_eq!(sd.install_route, ChannelInstallRoute::SdTrialBootOnly);
    assert!(payload
        .targets
        .iter()
        .all(|row| row.url.starts_with("https://")));
}
