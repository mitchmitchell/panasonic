#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use kxprov_api::{DiffHash, PlanId, Profile, TokenId};
use kxprovd::apply::{run_apply, ApplyError};
use kxprovd::backup::BackupStore;
use kxprovd::config::{Config, ConfigError, TransportKind};
use kxprovd::plan_store::PlanStore;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const FIXTURE_SIGNON: &str = r#"{"banner":"<FIXTURE_BANNER>","password_prompt":"<FIXTURE_PROMPT>","mode_start":"<FIXTURE_MODE_START>","in_use":"<FIXTURE_IN_USE>"}"#;

fn write_mode(path: &Path, body: &str, mode: u32) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn etc(dir: &Path, transport: &str, signon: Option<&Path>) -> PathBuf {
    let pass = dir.join("password");
    write_mode(&pass, "0000", 0o600);
    let signon = signon
        .map(|p| format!(r#","signon_path":"{}""#, p.display()))
        .unwrap_or_default();
    let gateway_uid = nix::unistd::getuid().as_raw().wrapping_add(1);
    let admin_uid = nix::unistd::getuid().as_raw();
    let cfg = dir.join("kxprovd.json");
    std::fs::write(
        &cfg,
        format!(
            r#"{{"password_path":"{}","provision_root":"{}","gateway_uid":{gateway_uid},"admin_uid":{admin_uid},"transport":"{transport}","serial_device":"/nonexistent/test-only"{signon}}}"#,
            pass.display(),
            dir.join("root").display()
        ),
    )
    .unwrap();
    cfg
}

#[test]
fn serial_transport_without_signon_file_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let err = Config::load_from_etc(etc(d.path(), "serial", None)).unwrap_err();
    assert!(matches!(err, ConfigError::SignOnRequired), "{err}");
}

#[test]
fn sim_transport_keeps_placeholder_signon() {
    let d = tempfile::tempdir().unwrap();
    let cfg = Config::load_from_etc(etc(d.path(), "sim", None)).unwrap();
    assert_eq!(cfg.signon, kxtd1232::SignOn::default());
}

#[test]
fn private_signon_file_is_loaded() {
    let d = tempfile::tempdir().unwrap();
    let s = d.path().join("signon.json");
    write_mode(&s, FIXTURE_SIGNON, 0o600);
    let cfg = Config::load_from_etc(etc(d.path(), "serial", Some(&s))).unwrap();
    assert_eq!(cfg.transport, TransportKind::Serial);
    assert_eq!(cfg.signon.password_prompt, "<FIXTURE_PROMPT>");
    assert_eq!(cfg.signon.mode_start, "<FIXTURE_MODE_START>");
}

#[test]
fn group_or_world_readable_signon_file_is_refused() {
    for mode in [0o640, 0o604, 0o644] {
        let d = tempfile::tempdir().unwrap();
        let s = d.path().join("signon.json");
        write_mode(&s, FIXTURE_SIGNON, mode);
        let err = Config::load_from_etc(etc(d.path(), "serial", Some(&s))).unwrap_err();
        assert!(
            matches!(err, ConfigError::SignOnPermissions(_)),
            "{mode:o}: {err}"
        );
    }
}

#[test]
fn empty_or_unknown_signon_fields_are_refused() {
    let d = tempfile::tempdir().unwrap();
    let s = d.path().join("signon.json");
    write_mode(
        &s,
        r#"{"banner":"","password_prompt":" ","mode_start":"m","in_use":"u"}"#,
        0o600,
    );
    let err = Config::load_from_etc(etc(d.path(), "serial", Some(&s))).unwrap_err();
    assert!(
        matches!(err, ConfigError::SignOnEmpty("password_prompt")),
        "{err}"
    );
    write_mode(
        &s,
        r#"{"banner":"b","password_prompt":"p","mode_start":"m","in_use":"u","extra":"x"}"#,
        0o600,
    );
    let err = Config::load_from_etc(etc(d.path(), "serial", Some(&s))).unwrap_err();
    assert!(matches!(err, ConfigError::Json(_)), "{err}");
}

#[test]
fn apply_is_refused_on_the_serial_transport_before_any_io() {
    let d = tempfile::tempdir().unwrap();
    let s = d.path().join("signon.json");
    write_mode(&s, FIXTURE_SIGNON, 0o600);
    let cfg = Config::load_from_etc(etc(d.path(), "serial", Some(&s))).unwrap();
    let plans = PlanStore::new(d.path().join("plans")).unwrap();
    let backups = BackupStore::new(d.path().join("backups")).unwrap();
    let err = run_apply(
        &cfg,
        Profile::Prod,
        &plans,
        &backups,
        &PlanId("0".repeat(32)),
        &DiffHash("0".repeat(64)),
        &TokenId("t".into()),
    )
    .unwrap_err();
    assert!(matches!(err, ApplyError::NotSim), "{err}");
}
