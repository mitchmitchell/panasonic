//! Root-only `.epoch/` counter storage (P4-R10).

use crate::config::{profile_epoch_counter_path, EPOCH_DIR_NAME};
use kxprov_api::Profile;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum EpochError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("epoch storage must be mode 0700 and root-owned")]
    InsecureDir,
    #[error("epoch counter must be mode 0600 and root-owned")]
    InsecureCounter,
    #[error("epoch counter corrupt or unreadable")]
    Corrupt,
}

pub fn epoch_dir(provision_root: &Path) -> PathBuf {
    provision_root.join(EPOCH_DIR_NAME)
}

#[cfg(unix)]
fn enforce_root_epoch_permissions() -> bool {
    nix::unistd::geteuid().is_root()
}

#[cfg(not(unix))]
fn enforce_root_epoch_permissions() -> bool {
    false
}

pub fn ensure_epoch_dir(provision_root: &Path) -> Result<(), EpochError> {
    let dir = epoch_dir(provision_root);
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if enforce_root_epoch_permissions() {
            let meta = std::fs::metadata(&dir)?;
            if meta.uid() != 0 || meta.mode() & 0o777 != 0o700 {
                return Err(EpochError::InsecureDir);
            }
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(unix)]
fn check_counter_secure(path: &Path) -> Result<(), EpochError> {
    use std::os::unix::fs::MetadataExt;
    if !enforce_root_epoch_permissions() {
        return Ok(());
    }
    if !path.exists() {
        return Ok(());
    }
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(EpochError::InsecureCounter);
    }
    if meta.uid() != 0 || meta.mode() & 0o777 != 0o600 {
        return Err(EpochError::InsecureCounter);
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_counter_secure(_path: &Path) -> Result<(), EpochError> {
    Ok(())
}

pub fn read_counter(provision_root: &Path, profile: Profile) -> Result<Option<u64>, EpochError> {
    let path = profile_epoch_counter_path(provision_root, profile);
    check_counter_secure(&path)?;
    if !path.exists() {
        return Ok(None);
    }
    let s = std::fs::read_to_string(&path)?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(EpochError::Corrupt);
    }
    trimmed.parse().map(Some).map_err(|_| EpochError::Corrupt)
}

pub fn write_counter(
    provision_root: &Path,
    profile: Profile,
    counter: u64,
) -> Result<(), EpochError> {
    ensure_epoch_dir(provision_root)?;
    let path = profile_epoch_counter_path(provision_root, profile);
    crate::atomic_write::write(&path, counter.to_string().as_bytes())?;
    check_counter_secure(&path)?;
    Ok(())
}
