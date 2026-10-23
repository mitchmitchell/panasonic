//! Atomic tokens.json writes (temp → fsync → rename) with mode 0600 on Unix.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

pub fn atomic_write_tokens(path: &Path, data: &[u8]) -> std::io::Result<()> {
    atomic_write_tokens_inner(path, data, |_| Ok(()))
}

pub(crate) fn atomic_write_tokens_inner(
    path: &Path,
    data: &[u8],
    before_rename: impl FnOnce(&Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("tokens"),
        std::process::id()
    ));
    {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    before_rename(&tmp)?;
    std::fs::rename(&tmp, path)?;
    if let Ok(dirf) = File::open(dir) {
        let _ = dirf.sync_all();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn temp_file_mode_0600_before_rename() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        atomic_write_tokens_inner(&path, b"{}", |tmp| {
            let mode = std::fs::metadata(tmp)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "temp tokens file must be 0600 before rename");
            Ok(())
        })
        .unwrap();
        let final_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(final_mode, 0o600);
    }
}
