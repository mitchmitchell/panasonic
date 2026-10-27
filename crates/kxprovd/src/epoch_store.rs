//! Root-only `.epoch/` counter storage (P4-R10).

use crate::config::{highest_epoch_counter_path, profile_epoch_counter_path, EPOCH_DIR_NAME};
use kxprov_api::Profile;
use std::path::{Path, PathBuf};
#[cfg(feature = "test-util")]
use std::sync::atomic::{AtomicBool, Ordering};

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

#[cfg(feature = "test-util")]
thread_local! {
    static EPOCH_SECURE_CHECKS: AtomicBool = const { AtomicBool::new(false) };
}

pub fn epoch_dir(provision_root: &Path) -> PathBuf {
    provision_root.join(EPOCH_DIR_NAME)
}

#[cfg(feature = "test-util")]
pub fn set_epoch_secure_checks_for_test(enforce: bool) {
    EPOCH_SECURE_CHECKS.with(|c| c.store(enforce, Ordering::Relaxed));
}

/// Enables epoch secure checks for the rest of this scope (test-util only).
#[cfg(feature = "test-util")]
pub struct EpochSecureChecksGuard(());

#[cfg(feature = "test-util")]
impl EpochSecureChecksGuard {
    pub fn enable() -> Self {
        set_epoch_secure_checks_for_test(true);
        Self(())
    }
}

#[cfg(feature = "test-util")]
impl Drop for EpochSecureChecksGuard {
    fn drop(&mut self) {
        set_epoch_secure_checks_for_test(false);
    }
}

fn secure_checks_enabled() -> bool {
    #[cfg(feature = "test-util")]
    if EPOCH_SECURE_CHECKS.with(|c| c.load(Ordering::Relaxed)) {
        return true;
    }
    #[cfg(unix)]
    {
        nix::unistd::geteuid().is_root()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(unix)]
fn required_owner_uid() -> u32 {
    #[cfg(feature = "test-util")]
    if EPOCH_SECURE_CHECKS.with(|c| c.load(Ordering::Relaxed)) {
        return nix::unistd::geteuid().as_raw();
    }
    0
}

#[cfg(not(unix))]
fn required_owner_uid() -> u32 {
    0
}

#[cfg(unix)]
fn check_epoch_dir_secure(dir: &Path) -> Result<(), EpochError> {
    use std::os::unix::fs::MetadataExt;
    if !secure_checks_enabled() {
        return Ok(());
    }
    let meta = std::fs::symlink_metadata(dir)?;
    if meta.file_type().is_symlink() {
        return Err(EpochError::InsecureDir);
    }
    if !meta.is_dir() {
        return Err(EpochError::InsecureDir);
    }
    let owner = required_owner_uid();
    if meta.uid() != owner || meta.mode() & 0o777 != 0o700 {
        return Err(EpochError::InsecureDir);
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_epoch_dir_secure(_dir: &Path) -> Result<(), EpochError> {
    Ok(())
}

pub fn ensure_epoch_dir(provision_root: &Path) -> Result<(), EpochError> {
    std::fs::create_dir_all(provision_root)?;
    let dir = epoch_dir(provision_root);
    if dir.symlink_metadata().is_ok() {
        check_epoch_dir_secure(&dir)?;
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(EpochError::Io(e)),
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(&dir)?;
    }
    check_epoch_dir_secure(&dir)?;
    Ok(())
}

#[cfg(unix)]
fn check_counter_secure(path: &Path) -> Result<(), EpochError> {
    use std::os::unix::fs::MetadataExt;
    if !secure_checks_enabled() {
        return Ok(());
    }
    if !path.exists() {
        return Ok(());
    }
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(EpochError::InsecureCounter);
    }
    let owner = required_owner_uid();
    if meta.uid() != owner || meta.mode() & 0o777 != 0o600 {
        return Err(EpochError::InsecureCounter);
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_counter_secure(_path: &Path) -> Result<(), EpochError> {
    Ok(())
}

fn check_epoch_dir_if_present(provision_root: &Path) -> Result<(), EpochError> {
    let dir = epoch_dir(provision_root);
    match dir.symlink_metadata() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(EpochError::Io(e)),
        Ok(_) => check_epoch_dir_secure(&dir),
    }
}

pub fn read_counter(provision_root: &Path, profile: Profile) -> Result<Option<u64>, EpochError> {
    check_epoch_dir_if_present(provision_root)?;
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
    bump_highest_epoch(provision_root, counter)?;
    Ok(())
}

/// `None` when `highest.counter` is absent; `Err(Corrupt)` when present but unreadable.
pub fn read_highest_epoch_file(provision_root: &Path) -> Result<Option<u64>, EpochError> {
    check_epoch_dir_if_present(provision_root)?;
    let path = highest_epoch_counter_path(provision_root);
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

pub fn read_highest_epoch(provision_root: &Path) -> Result<u64, EpochError> {
    Ok(read_highest_epoch_file(provision_root)?.unwrap_or(0))
}

pub fn bump_highest_epoch(provision_root: &Path, counter: u64) -> Result<(), EpochError> {
    ensure_epoch_dir(provision_root)?;
    let current = read_highest_epoch(provision_root)?;
    if counter <= current {
        return Ok(());
    }
    let path = highest_epoch_counter_path(provision_root);
    crate::atomic_write::write(&path, counter.to_string().as_bytes())?;
    check_counter_secure(&path)?;
    Ok(())
}

/// Highest epoch implied by `highest.counter` and the given profile counter files.
pub fn effective_highest_for_profiles(
    provision_root: &Path,
    profiles: &[Profile],
) -> Result<u64, EpochError> {
    let mut profile_max = 0u64;
    for &profile in profiles {
        if let Some(n) = read_counter(provision_root, profile)? {
            profile_max = profile_max.max(n);
        }
    }
    match read_highest_epoch_file(provision_root)? {
        None => Ok(profile_max),
        Some(h) => {
            if profile_max > 0 && h < profile_max {
                return Err(EpochError::Corrupt);
            }
            Ok(h.max(profile_max))
        }
    }
}

#[cfg(all(test, feature = "test-util"))]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::config::highest_epoch_counter_path;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn effective_highest_for_profiles_is_max_of_highest_and_counters() {
        let tmp = tempfile::tempdir().unwrap();
        write_counter(tmp.path(), Profile::Sim, 5).unwrap();
        write_counter(tmp.path(), Profile::Test, 3).unwrap();
        bump_highest_epoch(tmp.path(), 4).unwrap();
        let profiles = [Profile::Sim, Profile::Test];
        assert_eq!(
            effective_highest_for_profiles(tmp.path(), &profiles).unwrap(),
            5
        );
        std::fs::write(highest_epoch_counter_path(tmp.path()), b"2\n").unwrap();
        assert!(matches!(
            effective_highest_for_profiles(tmp.path(), &profiles),
            Err(EpochError::Corrupt)
        ));
    }

    #[test]
    fn read_treats_missing_epoch_dir_as_no_counter_yet() {
        let _secure = EpochSecureChecksGuard::enable();
        let tmp = tempfile::tempdir().unwrap();
        assert!(!epoch_dir(tmp.path()).exists());
        assert_eq!(read_counter(tmp.path(), Profile::Prod).unwrap(), None);
    }

    #[test]
    fn fresh_install_creates_epoch_dir_mode_0700() {
        let _secure = EpochSecureChecksGuard::enable();
        let tmp = tempfile::tempdir().unwrap();
        assert!(!epoch_dir(tmp.path()).exists());
        write_counter(tmp.path(), Profile::Sim, 1).unwrap();
        let meta = std::fs::symlink_metadata(epoch_dir(tmp.path())).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o700);
        assert_eq!(meta.uid(), nix::unistd::geteuid().as_raw());
    }

    #[cfg(unix)]
    #[test]
    fn read_rejects_world_writable_epoch_dir() {
        let _secure = EpochSecureChecksGuard::enable();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path()).unwrap();
        let dir = epoch_dir(tmp.path());
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            read_counter(tmp.path(), Profile::Sim),
            Err(EpochError::InsecureDir)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn read_rejects_symlink_epoch_dir() {
        let _secure = EpochSecureChecksGuard::enable();
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("epoch-real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, epoch_dir(tmp.path())).unwrap();
        assert!(matches!(
            read_counter(tmp.path(), Profile::Sim),
            Err(EpochError::InsecureDir)
        ));
    }
}
