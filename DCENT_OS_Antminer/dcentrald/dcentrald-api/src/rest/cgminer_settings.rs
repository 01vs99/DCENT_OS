//! The persisted monitoring controls are distinct from the running listener.
use serde::Serialize;

#[derive(Debug, Serialize, PartialEq)]
pub(super) struct Settings {
    cgminer_bind_lan: bool,
    cgminer_lan_writes: bool,
}

pub(super) fn saved(table: &toml::Table) -> Result<Settings, String> {
    let api = table
        .get("api")
        .map(|value| {
            value
                .as_table()
                .ok_or_else(|| "api must be a table".to_string())
        })
        .transpose()?;
    let flag = |key, default| match api.and_then(|api| api.get(key)) {
        None => Ok(default),
        Some(value) => value
            .as_bool()
            .ok_or_else(|| format!("api.{key} must be a boolean")),
    };
    Ok(Settings {
        cgminer_bind_lan: flag("cgminer_bind_lan", true)?,
        cgminer_lan_writes: flag("cgminer_lan_writes", false)?,
    })
}

pub(super) fn validate(table: &toml::Table) -> Result<(), String> {
    saved(table).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn actual_config_merge_preserves_separate_listener_and_write_choices() {
        for (lan, writes) in [(true, false), (false, false), (true, true)] {
            let base: toml::Table = "[api]\nhttp_port=8080\n[pool]\nworker='private-worker'\n"
                .parse()
                .unwrap();
            let merged = super::super::merge_config_update_table(
                base,
                &json!({"api": {
                    "cgminer_bind_lan": lan, "cgminer_lan_writes": writes
                }}),
            )
            .unwrap();
            let serialized = toml::to_string(&merged).unwrap();
            let persisted: toml::Table = serialized.parse().unwrap();
            assert_eq!(
                saved(&persisted).unwrap(),
                Settings {
                    cgminer_bind_lan: lan,
                    cgminer_lan_writes: writes
                }
            );
            assert_eq!(persisted["api"]["http_port"].as_integer(), Some(8080));
            assert_eq!(persisted["pool"]["worker"].as_str(), Some("private-worker"));
        }
        assert_eq!(
            saved(&toml::Table::new()).unwrap(),
            Settings {
                cgminer_bind_lan: true,
                cgminer_lan_writes: false
            }
        );
    }

    #[test]
    fn actual_config_merge_refuses_nonboolean_controls_before_persistence() {
        for field in ["cgminer_bind_lan", "cgminer_lan_writes"] {
            for value in [json!("true"), json!(1), json!(null), json!([]), json!({})] {
                let update = json!({"api": {field: value}});
                assert!(
                    super::super::merge_config_update_table(toml::Table::new(), &update).is_err(),
                    "{update}"
                );
            }
        }
        assert!(super::super::merge_config_update_table(
            toml::Table::new(),
            &json!({"api": "true"})
        )
        .is_err());
    }
}
