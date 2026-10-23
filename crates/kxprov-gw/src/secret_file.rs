//! Secret file resolution (`CREDENTIALS_DIRECTORY`) and ownership/mode checks for non-root gateway.

use std::fs;
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
    validate_secret_file_with_group(path, label, Some(GATEWAY_SECRET_GROUP))
}

pub fn validate_secret_file_with_group(
    path: &Path,
    label: &str,
    group_for_root_owned: Option<&str>,
) -> anyhow::Result<()> {
    if skip_secret_file_checks() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if path.is_symlink() {
            anyhow::bail!("{label} file must not be a symlink");
        }
        let meta = fs::symlink_metadata(path)?;
        let mode = meta.mode();
        if mode & 0o022 != 0 {
            anyhow::bail!("{label} file must not be group- or world-writable");
        }
        let perm = mode & 0o777;
        let euid = nix::unistd::geteuid().as_raw();
        let uid = meta.uid();

        if is_under_credentials_directory(path) {
            if uid != 0 {
                anyhow::bail!("{label} credential must be owned by root (uid 0)");
            }
            if perm != 0o600 && perm != 0o400 {
                anyhow::bail!("{label} credential must be mode 0600 or 0400");
            }
            return Ok(());
        }

        if uid == euid && (perm == 0o600 || perm == 0o400) {
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
        let _ = (path, label, group_for_root_owned);
        Ok(())
    }
}

fn is_under_credentials_directory(path: &Path) -> bool {
    let Ok(cred_dir) = std::env::var("CREDENTIALS_DIRECTORY") else {
        return false;
    };
    let cred = PathBuf::from(cred_dir);
    path.starts_with(&cred)
}

#[cfg(any(test, feature = "test-secret-skip"))]
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
    use std::os::unix::fs::PermissionsExt;

    fn write_secret(path: &Path, body: &str, mode: u32) {
        std::fs::write(path, body).unwrap();
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(mode);
        std::fs::set_permissions(path, perms).unwrap();
    }

    #[test]
    fn rejects_symlink_secret() {
        std::env::remove_var("KXPROV_SKIP_SECRET_FILE_CHECKS");
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real");
        write_secret(&target, "x", 0o600);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = validate_secret_file(&link, "test").unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[test]
    fn rejects_group_writable() {
        std::env::remove_var("KXPROV_SKIP_SECRET_FILE_CHECKS");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        write_secret(&path, "x", 0o660);
        let err = validate_secret_file(&path, "test").unwrap_err();
        assert!(err.to_string().contains("writable"), "{err}");
    }

    #[test]
    fn accepts_owner_euid_mode_0600() {
        std::env::remove_var("KXPROV_SKIP_SECRET_FILE_CHECKS");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        write_secret(&path, "x", 0o600);
        validate_secret_file(&path, "test").expect("owner 0600");
    }

    #[test]
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
