#![allow(
    clippy::unwrap_used,
    reason = "test setup failures should abort the test"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use kxprovd::config::{
    Config, ConfigError, SmdrConfig, DEFAULT_CTS_LOW_ALERT_AFTER_SECS,
    DEFAULT_SILENCE_ALERT_AFTER_SECS,
};
use std::time::Duration;

fn etc(dir: &Path, extra: &str) -> PathBuf {
    let pass = dir.join("password");
    std::fs::write(&pass, "0000").unwrap();
    std::fs::set_permissions(&pass, std::fs::Permissions::from_mode(0o600)).unwrap();
    let gateway_uid = nix::unistd::getuid().as_raw().wrapping_add(1);
    let admin_uid = nix::unistd::getuid().as_raw();
    let cfg = dir.join("kxprovd.json");
    std::fs::write(
        &cfg,
        format!(
            r#"{{"password_path":"{}","provision_root":"{}","gateway_uid":{gateway_uid},"admin_uid":{admin_uid},"transport":"sim"{extra}}}"#,
            pass.display(),
            dir.join("root").display()
        ),
    )
    .unwrap();
    cfg
}

#[test]
fn call_log_is_on_unless_the_config_turns_it_off() {
    let d = tempfile::tempdir().unwrap();
    let on = Config::load_from_etc(etc(d.path(), "")).unwrap();
    assert_eq!(on.smdr, SmdrConfig::default());
    assert!(on.smdr.enabled);
    let empty = Config::load_from_etc(etc(d.path(), r#","smdr":{}"#)).unwrap();
    assert!(empty.smdr.enabled);
    let off = Config::load_from_etc(etc(d.path(), r#","smdr":{"enabled":false}"#)).unwrap();
    assert!(!off.smdr.enabled);
}

#[test]
fn unknown_smdr_keys_are_refused() {
    let d = tempfile::tempdir().unwrap();
    assert!(Config::load_from_etc(etc(d.path(), r#","smdr":{"enable":false}"#)).is_err());
}

#[test]
fn health_thresholds_default_and_load_from_config() {
    let d = tempfile::tempdir().unwrap();
    let on = Config::load_from_etc(etc(d.path(), "")).unwrap();
    assert_eq!(
        on.smdr.silence_alert_after,
        DEFAULT_SILENCE_ALERT_AFTER_SECS
    );
    assert_eq!(
        on.smdr.cts_low_alert_after,
        DEFAULT_CTS_LOW_ALERT_AFTER_SECS
    );
    assert!(on.smdr.cts_monitor);
    let set = Config::load_from_etc(etc(
        d.path(),
        r#","smdr":{"silence_alert_after":600,"cts_low_alert_after":5,"cts_monitor":false}"#,
    ))
    .unwrap();
    let health = set.smdr.health().unwrap();
    assert_eq!(health.silence_after, Duration::from_secs(600));
    assert_eq!(health.cts_low_after, Duration::from_secs(5));
    assert!(!health.cts_monitor);
}

#[test]
fn zero_or_negative_thresholds_are_rejected_at_load_naming_the_key() {
    let d = tempfile::tempdir().unwrap();
    for (key, value) in [
        ("silence_alert_after", "0"),
        ("silence_alert_after", "-5"),
        ("cts_low_alert_after", "0"),
        ("cts_low_alert_after", "-1"),
    ] {
        let extra = format!(r#","smdr":{{"{key}":{value}}}"#);
        let err = Config::load_from_etc(etc(d.path(), &extra)).unwrap_err();
        assert!(
            matches!(&err, ConfigError::NotPositive { key: k, .. } if *k == format!("smdr.{key}")),
            "{key}={value}: {err}"
        );
        assert!(err.to_string().contains(&format!("smdr.{key}")));
    }
}
