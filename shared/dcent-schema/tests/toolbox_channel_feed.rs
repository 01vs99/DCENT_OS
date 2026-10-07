use dcent_schema::update::{ChannelFeed, ChannelFeedPayload, ToolboxChannelFeedPayload,
    ToolboxPlatformTarget, ToolboxArtifactKind};

#[test]
fn toolbox_channel_fixture_uses_shared_envelope_and_exact_host_types() {
    let envelope: ChannelFeed = serde_json::from_str(include_str!("fixtures/toolbox_channel_feed.json")).unwrap();
    let payload: ToolboxChannelFeedPayload = serde_json::from_str(&envelope.payload).unwrap();
    assert_eq!(payload.targets.len(), 3);
    assert_eq!(payload.targets[0].platform_target, ToolboxPlatformTarget::WindowsX86_64);
    assert_eq!(payload.targets[0].artifact_kind, ToolboxArtifactKind::WindowsInstaller);
    assert!(serde_json::from_str::<ChannelFeedPayload>(&envelope.payload).is_err());
    for (field, value) in [("platform_target", "windows-arm64"), ("artifact_kind", "sysupgrade-tar")] {
        let mut value_json: serde_json::Value = serde_json::from_str(&envelope.payload).unwrap();
        value_json["targets"][0][field] = serde_json::json!(value);
        assert!(serde_json::from_value::<ToolboxChannelFeedPayload>(value_json).is_err());
    }
    let duplicate = envelope.payload.replace("\"product\":\"DCENT_TOOLBOX\"", "\"product\":\"DCENT_TOOLBOX\",\"product\":\"DCENT_TOOLBOX\"");
    assert!(serde_json::from_str::<ToolboxChannelFeedPayload>(&duplicate).is_err());
    let foreign = envelope.payload.replace("DCENT_TOOLBOX", "DCENT_OS");
    assert!(serde_json::from_str::<ToolboxChannelFeedPayload>(&foreign).is_err());
}
