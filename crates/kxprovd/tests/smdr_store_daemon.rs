use kxprovd::smdr_store::{backup_sets, SmdrStore};
use kxtd1232::smdr::DateOrder;
use std::path::{Path, PathBuf};

#[test]
fn daemon_backup_sets_exclude_the_smdr_dir() {
    let tmp = tempfile::tempdir().expect("tmp");
    let config =
        kxprovd::config::Config::sim_test(tmp.path().to_path_buf(), tmp.path().join("s"), 0);
    let sets = backup_sets(&config);
    let refs: Vec<&Path> = sets.iter().map(PathBuf::as_path).collect();
    let store = SmdrStore::open(&config.data_dir, &refs, DateOrder::Mdy).expect("open");
    for set in &sets {
        assert!(!store.dir().starts_with(set), "{set:?}");
    }
}
