//! Secret file resolution (`CREDENTIALS_DIRECTORY`) and ownership/mode checks for non-root gateway.

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Primary gateway group for `root:<group>` mode `0640` secret files on disk.
pub const GATEWAY_SECRET_GROUP: &str = "kxprov-gw";

/// Prefer systemd `LoadCredential=` paths when present (`$CREDENTIALS_DIRECTORY/<basename>`).
pub fn resolve_secret_path(configured: &Path) -> PathBuf {
    let Some(name) = configured.file_name() else {
        return configured.to_path_buf();
    };
    if let Ok(cred_dir) = std::env::var("CREDENTIALS_DIRECTORY") {
        let candidate = PathBuf::from(cred_dir).join(name);
        if candidate.is_file() {
            return candidate;
        }
    }
    configured.to_path_buf()
}

pub fn validate_secret_file(path: &Path, label: &str) -> anyhow::Result<()> {
    let _ = open_validated_secret(path, label)?;
    Ok(())
}

/// Open a secret with `O_NOFOLLOW`, validate metadata from the open fd, return handle for reading.
pub fn open_validated_secret(path: &Path, label: &str) -> anyhow::Result<File> {
    let path = resolve_secret_path(path);
    open_validated_secret_resolved(&path, label)
}

fn open_validated_secret_resolved(path: &Path, label: &str) -> anyhow::Result<File> {
    #[cfg(unix)]
    {
        use nix::fcntl::OFlag;
        use std::os::unix::fs::OpenOptionsExt;

        use std::os::unix::fs::FileTypeExt;

        let file = OpenOptions::new()
            .read(true)
            .custom_flags(OFlag::O_NOFOLLOW.bits() | OFlag::O_NONBLOCK.bits())
            .open(path)
            .map_err(|e| anyhow::anyhow!("{label}: open: {e}"))?;
        let meta = file
            .metadata()
            .map_err(|e| anyhow::anyhow!("{label}: fstat: {e}"))?;
        if meta.file_type().is_fifo() {
            anyhow::bail!("{label}: refusing FIFO special file");
        }
        if !meta.is_file() {
            anyhow::bail!("{label}: must be a regular file");
        }
        validate_secret_metadata(&meta, path, label, Some(GATEWAY_SECRET_GROUP))?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = label;
        fs::File::open(path).map_err(Into::into)
    }
}

/// Read entire secret after validation (single fd; no check-then-reopen by path).
pub fn read_secret_file(path: &Path, label: &str) -> anyhow::Result<String> {
    let mut file = open_validated_secret(path, label)?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .map_err(|e| anyhow::anyhow!("{label}: read: {e}"))?;
    Ok(buf)
}

fn validate_secret_metadata(
    meta: &fs::Metadata,
    path_for_cred: &Path,
    label: &str,
    group_for_root_owned: Option<&str>,
) -> anyhow::Result<()> {
    if skip_secret_file_checks() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let mode = meta.mode();
        if mode & 0o022 != 0 {
            anyhow::bail!("{label} file must not be group- or world-writable");
        }
        let perm = mode & 0o777;
        let euid = nix::unistd::geteuid().as_raw();
        let uid = meta.uid();

        if is_under_credentials_directory(path_for_cred) {
            return validate_credentials_directory_metadata(uid, euid, perm, label);
        }

        if uid == euid && matches!(perm, 0o600 | 0o400) {
            return Ok(());
        }

        if uid == 0 && perm == 0o600 {
            return Ok(());
        }

        if uid == 0 && perm == 0o640 {
            let Some(group_name) = group_for_root_owned else {
                anyhow::bail!("{label} file is mode 0640 but no gateway group is configured");
            };
            let expected_gid = nix::unistd::Group::from_name(group_name)
                .map_err(|e| anyhow::anyhow!("{label} group lookup: {e}"))?
                .ok_or_else(|| anyhow::anyhow!("{label} group {group_name:?} not found"))?
                .gid;
            if meta.gid() != expected_gid.as_raw() {
                anyhow::bail!(
                    "{label} file must be owned by root:{group_name} (mode 0640) or uid {euid} (mode 0600)"
                );
            }
            return Ok(());
        }

        anyhow::bail!(
            "{label} file must be owned by uid {euid} (mode 0600), root (mode 0600), \
             root:{group_for_root_owned:?} (mode 0640), or a LoadCredential under \
             $CREDENTIALS_DIRECTORY"
        );
    }
    #[cfg(not(unix))]
    {
        let _ = (meta, path_for_cred, label, group_for_root_owned);
        Ok(())
    }
}

/// Modes systemd commonly uses for `LoadCredential=` (root-owned, service-readable via ACL).
fn validate_credentials_directory_metadata(
    uid: u32,
    euid: u32,
    perm: u32,
    label: &str,
) -> anyhow::Result<()> {
    if !matches!(perm, 0o400 | 0o440 | 0o600) {
        anyhow::bail!("{label} credential must be mode 0400, 0440, or 0600 (got {perm:o})");
    }
    if uid == euid {
        return Ok(());
    }
    if uid == 0 {
        return Ok(());
    }
    anyhow::bail!(
        "{label} credential must be owned by root (uid 0) or the service user (uid {euid})"
    );
}

fn is_under_credentials_directory(path: &Path) -> bool {
    let Ok(cred_dir) = std::env::var("CREDENTIALS_DIRECTORY") else {
        return false;
    };
    let cred = PathBuf::from(cred_dir);
    path.starts_with(&cred)
}

#[cfg(test)]
thread_local! {
    static SKIP_SECRET_FILE_CHECKS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Sets the unit-test skip flag for the calling thread only, so parallel
/// tests cannot flip each other's secret-file checks (issue #83).
#[cfg(test)]
pub(crate) fn set_skip_secret_file_checks(skip: bool) {
    SKIP_SECRET_FILE_CHECKS.with(|flag| flag.set(skip));
}

#[cfg(test)]
pub(crate) fn skip_secret_file_checks() -> bool {
    SKIP_SECRET_FILE_CHECKS.with(std::cell::Cell::get)
}

#[cfg(all(not(test), feature = "test-secret-skip"))]
pub(crate) fn skip_secret_file_checks() -> bool {
    std::env::var("KXPROV_SKIP_SECRET_FILE_CHECKS")
        .ok()
        .as_deref()
        == Some("1")
}

#[cfg(not(any(test, feature = "test-secret-skip")))]
pub(crate) fn skip_secret_file_checks() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::os::unix::fs::PermissionsExt;

    fn write_secret(path: &Path, body: &str, mode: u32) {
        std::fs::write(path, body).unwrap();
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(mode);
        std::fs::set_permissions(path, perms).unwrap();
    }

    #[test]
    fn rejects_symlink_secret() {
        set_skip_secret_file_checks(false);
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real");
        write_secret(&target, "x", 0o600);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = open_validated_secret(&link, "test").unwrap_err();
        assert!(
            err.to_string().contains("open") || err.to_string().contains("symlink"),
            "{err}"
        );
    }

    #[test]
    fn rejects_group_writable() {
        set_skip_secret_file_checks(false);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        write_secret(&path, "x", 0o660);
        let err = validate_secret_file(&path, "test").unwrap_err();
        assert!(err.to_string().contains("writable"), "{err}");
    }

    #[test]
    fn accepts_owner_euid_mode_0600() {
        set_skip_secret_file_checks(false);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        write_secret(&path, "x", 0o600);
        validate_secret_file(&path, "test").expect("owner 0600");
    }

    #[test]
    #[serial]
    fn accepts_credential_mode_0440_root_owned() {
        set_skip_secret_file_checks(false);
        let dir = tempfile::tempdir().unwrap();
        let cred = dir.path().join("creds");
        std::fs::create_dir_all(&cred).unwrap();
        let path = cred.join("lan.key");
        write_secret(&path, "key-data", 0o440);
        std::env::set_var("CREDENTIALS_DIRECTORY", cred.to_str().unwrap());
        read_secret_file(&path, "TLS private key").expect("0440 credential");
        std::env::remove_var("CREDENTIALS_DIRECTORY");
    }

    #[test]
    #[serial]
    fn resolve_prefers_credentials_directory() {
        let dir = tempfile::tempdir().unwrap();
        let cred = dir.path().join("creds");
        std::fs::create_dir_all(&cred).unwrap();
        let configured = dir.path().join("etc/admin.hash");
        write_secret(&cred.join("admin.hash"), "from-cred", 0o600);
        std::env::set_var("CREDENTIALS_DIRECTORY", cred.to_str().unwrap());
        let resolved = resolve_secret_path(&configured);
        assert_eq!(resolved, cred.join("admin.hash"));
        std::env::remove_var("CREDENTIALS_DIRECTORY");
    }
}
