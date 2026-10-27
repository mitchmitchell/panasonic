//! Atomic, durable state writes (temp → fsync → rename).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

fn atomic_temp_path(dir: &Path, base: &str) -> PathBuf {
    let mut rnd = [0u8; 8];
    let _ = getrandom::fill(&mut rnd);
    dir.join(format!(
        ".{}.tmp.{}.{}",
        base,
        std::process::id(),
        hex::encode(rnd)
    ))
}

pub fn write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let base = path.file_name().and_then(|s| s.to_str()).unwrap_or("file");
    let tmp = atomic_temp_path(dir, base);
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
    std::fs::rename(&tmp, path)?;
    if let Ok(dirf) = File::open(dir) {
        let _ = dirf.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn stale_pid_temp_does_not_block_atomic_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let stale = dir
            .path()
            .join(format!(".state.json.tmp.{}", std::process::id()));
        std::fs::write(&stale, b"leftover").unwrap();
        write(&path, b"{}").expect("write despite stale temp");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{}");
    }
}
