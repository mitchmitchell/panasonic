#![allow(
    clippy::unwrap_used,
    reason = "test setup failures should abort the test"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use kxprovd::config::{Config, SmdrConfig};

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
    assert_eq!(on.smdr, SmdrConfig { enabled: true });
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
