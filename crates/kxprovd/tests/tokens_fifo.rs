//! FIFO `tokens.json` reload: one probe thread, fast fail-closed auth under hang.

#![allow(clippy::unwrap_used)]
#![cfg(unix)]

use kxprov_api::Scope;
use kxprovd::tokens::{TokenError, TokenStore};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn fifo_test_serial_lock() -> std::sync::MutexGuard<'static, ()> {
    FIFO_THREAD_TESTS_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

static FIFO_THREAD_TESTS_LOCK: Mutex<()> = Mutex::new(());

fn write_tokens(path: &std::path::Path) {
    let file = kxprovd::test_util::default_tokens_file();
    TokenStore::write_test_file(path, &file).expect("write tokens");
}

const MAX_LIVE_PROBE_THREADS: usize = TokenStore::MAX_LIVE_DISK_PROBE_THREADS;
const MAX_OS_THREAD_DELTA: usize = 2;

fn proc_self_task_count() -> usize {
    std::fs::read_dir("/proc/self/task")
        .map(|d| d.count())
        .unwrap_or(0)
}

fn wait_live_at_most_cap(store: &TokenStore, deadline: Instant) {
    while store.live_disk_probe_threads_for_test() > MAX_LIVE_PROBE_THREADS {
        assert!(
            Instant::now() < deadline,
            "probe thread count did not fall (live={}, abandoned={})",
            store.live_disk_probe_threads_for_test(),
            store.leaked_disk_probe_threads_for_test()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_live_probe_threads_drained(store: &TokenStore, deadline: Instant) {
    while store.live_disk_probe_threads_for_test() > 0 {
        assert!(
            Instant::now() < deadline,
            "probe threads did not drain (live={}, abandoned={})",
            store.live_disk_probe_threads_for_test(),
            store.leaked_disk_probe_threads_for_test()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Open both FIFO ends concurrently so neither side blocks waiting for a peer.
fn write_bytes_through_fifo(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;
    let path = path.to_path_buf();
    let bytes = bytes.to_vec();
    std::thread::scope(|scope| {
        let path_read = path.clone();
        scope.spawn(move || {
            let _reader = std::fs::OpenOptions::new()
                .read(true)
                .open(&path_read)
                .expect("fifo read end for paired open");
            std::thread::sleep(Duration::from_secs(2));
        });
        scope.spawn(move || {
            let mut writer = std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .expect("fifo write end for paired open");
            writer.write_all(&bytes).expect("write tokens through fifo");
        });
    });
}

fn assert_probe_counts_bounded(store: &TokenStore) {
    assert!(
        store.live_disk_probe_threads_for_test() <= MAX_LIVE_PROBE_THREADS,
        "live probe threads {}",
        store.live_disk_probe_threads_for_test()
    );
}

fn auth_recovers_after_replace(store: &TokenStore, path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        assert_probe_counts_bounded(store);
        match store.verify_bearer(kxprovd::test_util::WRITER_SECRET, 0, Scope::Plan) {
            Ok(_) => break,
            Err(TokenError::StoreUnavailable) => {
                assert!(
                    Instant::now() < deadline,
                    "auth did not recover after tokens.json replace"
                );
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => panic!("unexpected token error: {e}"),
        }
    }
    assert!(
        store.live_disk_probe_threads_for_test() <= MAX_LIVE_PROBE_THREADS,
        "live probe threads after recovery"
    );
    assert!(
        path.is_file(),
        "expected regular tokens.json after recovery"
    );
}

#[test]
fn fifo_tokens_single_probe_thread_fast_fail_and_recovery() {
    let _lock = fifo_test_serial_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("tokens.json");
    write_tokens(&path);
    let store = Arc::new(TokenStore::load_insecure(path.clone()).expect("load"));
    store
        .verify_bearer(kxprovd::test_util::WRITER_SECRET, 0, Scope::Plan)
        .expect("warm");

    std::fs::remove_file(&path).expect("remove tokens");
    use nix::sys::stat::Mode;
    nix::unistd::mkfifo(&path, Mode::S_IRUSR | Mode::S_IWUSR).expect("mkfifo");

    let stop = Arc::new(AtomicBool::new(false));
    let max_live = Arc::new(AtomicUsize::new(0));
    let saw_outstanding = Arc::new(AtomicBool::new(false));
    let slow_calls = Arc::new(AtomicUsize::new(0));
    let fast_denies = Arc::new(AtomicUsize::new(0));
    let started = Instant::now();
    let wall = Duration::from_secs(15);
    let measure_fast_after = started + Duration::from_secs(3);

    let mut handles = Vec::new();
    for _ in 0..4 {
        let store = Arc::clone(&store);
        let stop = Arc::clone(&stop);
        let max_live = Arc::clone(&max_live);
        let saw_outstanding = Arc::clone(&saw_outstanding);
        let slow_calls = Arc::clone(&slow_calls);
        let fast_denies = Arc::clone(&fast_denies);
        handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) && started.elapsed() < wall {
                let live = store.live_disk_probe_threads_for_test();
                max_live.fetch_max(live, Ordering::Relaxed);
                if live > 0 {
                    saw_outstanding.store(true, Ordering::Relaxed);
                }
                let live_at_start = store.live_disk_probe_threads_for_test();
                let t0 = Instant::now();
                let res = store.verify_bearer(kxprovd::test_util::WRITER_SECRET, 0, Scope::Plan);
                let elapsed = t0.elapsed();
                match res {
                    Err(TokenError::StoreUnavailable)
                        if Instant::now() >= measure_fast_after && live_at_start > 0 =>
                    {
                        if elapsed <= Duration::from_millis(100) {
                            fast_denies.fetch_add(1, Ordering::Relaxed);
                        } else {
                            slow_calls.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(TokenError::StoreUnavailable) => {}
                    Ok(_) => {}
                    Err(e) => panic!("unexpected token error: {e}"),
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }));
    }

    while started.elapsed() < wall {
        std::thread::sleep(Duration::from_millis(50));
    }
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().expect("join");
    }

    assert!(
        saw_outstanding.load(Ordering::Relaxed),
        "expected an outstanding disk probe while FIFO blocked read"
    );
    assert!(
        max_live.load(Ordering::Relaxed) <= MAX_LIVE_PROBE_THREADS,
        "live probe threads peaked at {}",
        max_live.load(Ordering::Relaxed)
    );
    assert!(
        fast_denies.load(Ordering::Relaxed) > 0,
        "expected fast StoreUnavailable denials while probe was outstanding"
    );
    assert!(
        slow_calls.load(Ordering::Relaxed) <= 1,
        "calls after the first probe must not wait on the reload window (slow={})",
        slow_calls.load(Ordering::Relaxed)
    );

    wait_live_probe_threads_drained(&store, Instant::now() + Duration::from_secs(10));

    {
        let file = kxprovd::test_util::default_tokens_file();
        let bytes = serde_json::to_vec_pretty(&file).expect("json");
        write_bytes_through_fifo(&path, &bytes);
    }

    wait_live_at_most_cap(&store, Instant::now() + Duration::from_secs(5));

    std::fs::remove_file(&path).expect("remove fifo");
    write_tokens(&path);

    auth_recovers_after_replace(&store, &path);
}

#[test]
fn six_fifo_hangs_cap_live_threads_and_fast_fail_closed() {
    let _lock = fifo_test_serial_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("tokens.json");
    write_tokens(&path);
    let store = Arc::new(TokenStore::load_insecure(path.clone()).expect("load"));
    store
        .verify_bearer(kxprovd::test_util::WRITER_SECRET, 0, Scope::Plan)
        .expect("warm");

    let mut max_live = 0usize;
    for i in 0..6 {
        std::fs::remove_file(&path).ok();
        use nix::sys::stat::Mode;
        nix::unistd::mkfifo(&path, Mode::S_IRUSR | Mode::S_IWUSR).expect("mkfifo");
        store.set_reload_probe_hang_for_test(true);
        let starter = Arc::clone(&store);
        let starter_handle = std::thread::spawn(move || {
            let _ = starter.verify_bearer(kxprovd::test_util::WRITER_SECRET, 0, Scope::Plan);
        });
        let probe_deadline = Instant::now() + Duration::from_secs(5);
        while store.live_disk_probe_threads_for_test() == 0 {
            assert!(
                Instant::now() < probe_deadline,
                "iteration {i} probe never started"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        max_live = max_live.max(store.live_disk_probe_threads_for_test());
        let t0 = Instant::now();
        assert!(
            matches!(
                store.verify_bearer(kxprovd::test_util::WRITER_SECRET, 0, Scope::Plan),
                Err(TokenError::StoreUnavailable)
            ),
            "iteration {i} should fast-fail while fifo probe is outstanding"
        );
        assert!(
            t0.elapsed() <= Duration::from_millis(250),
            "iteration {i} fast-fail took {:?}",
            t0.elapsed()
        );
        assert!(
            store.live_disk_probe_threads_for_test() <= MAX_LIVE_PROBE_THREADS,
            "iteration {i} live={}",
            store.live_disk_probe_threads_for_test()
        );
        store.set_reload_probe_hang_for_test(false);
        std::fs::remove_file(&path).ok();
        write_tokens(&path);
        let _ = starter_handle.join();
        let drain = Instant::now() + Duration::from_secs(8);
        while store.live_disk_probe_threads_for_test() > 0 && Instant::now() < drain {
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            Instant::now() < drain,
            "iteration {i} probe threads did not drain"
        );
    }
    assert!(
        max_live <= MAX_LIVE_PROBE_THREADS,
        "peaked at {max_live} live probe threads"
    );
}

#[test]
fn five_fifo_replace_cycles_os_thread_count_bounded() {
    let _lock = fifo_test_serial_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("tokens.json");
    write_tokens(&path);
    let store = TokenStore::load_insecure(path.clone()).expect("load");
    store
        .verify_bearer(kxprovd::test_util::WRITER_SECRET, 0, Scope::Plan)
        .expect("warm");

    let baseline = proc_self_task_count();
    let mut peak_delta = 0usize;
    for i in 0..5 {
        std::fs::remove_file(&path).ok();
        use nix::sys::stat::Mode;
        nix::unistd::mkfifo(&path, Mode::S_IRUSR | Mode::S_IWUSR).expect("mkfifo");
        let _ = store.verify_bearer(kxprovd::test_util::WRITER_SECRET, 0, Scope::Plan);
        let delta = proc_self_task_count().saturating_sub(baseline);
        peak_delta = peak_delta.max(delta);
        assert!(
            store.live_disk_probe_threads_for_test() <= MAX_LIVE_PROBE_THREADS,
            "cycle {i} live={}",
            store.live_disk_probe_threads_for_test()
        );
        std::fs::remove_file(&path).ok();
        write_tokens(&path);
        auth_recovers_after_replace(&store, &path);
        let drain = Instant::now() + Duration::from_secs(3);
        while store.live_disk_probe_threads_for_test() > 0 && Instant::now() < drain {
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    assert!(
        peak_delta <= MAX_OS_THREAD_DELTA,
        "OS thread count grew by {peak_delta} (baseline {baseline})"
    );
}

#[test]
fn fifo_replaced_by_regular_file_via_rename_recovers_auth() {
    let _lock = fifo_test_serial_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("tokens.json");
    write_tokens(&path);
    let store = TokenStore::load_insecure(path.clone()).expect("load");
    store
        .verify_bearer(kxprovd::test_util::WRITER_SECRET, 0, Scope::Plan)
        .expect("warm");

    std::fs::remove_file(&path).expect("remove tokens");
    use nix::sys::stat::Mode;
    nix::unistd::mkfifo(&path, Mode::S_IRUSR | Mode::S_IWUSR).expect("mkfifo");
    let stress_until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < stress_until {
        let _ = store.verify_bearer(kxprovd::test_util::WRITER_SECRET, 0, Scope::Plan);
        std::thread::sleep(Duration::from_millis(20));
    }

    let replacement = tmp.path().join("tokens.replacement.json");
    write_tokens(&replacement);
    std::fs::rename(&replacement, &path).expect("rename regular file over fifo path");

    auth_recovers_after_replace(&store, &path);
}

#[test]
fn fifo_replaced_by_regular_file_via_unlink_create_recovers_auth() {
    let _lock = fifo_test_serial_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("tokens.json");
    write_tokens(&path);
    let store = TokenStore::load_insecure(path.clone()).expect("load");
    store
        .verify_bearer(kxprovd::test_util::WRITER_SECRET, 0, Scope::Plan)
        .expect("warm");

    std::fs::remove_file(&path).expect("remove tokens");
    use nix::sys::stat::Mode;
    nix::unistd::mkfifo(&path, Mode::S_IRUSR | Mode::S_IWUSR).expect("mkfifo");
    let stress_until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < stress_until {
        let _ = store.verify_bearer(kxprovd::test_util::WRITER_SECRET, 0, Scope::Plan);
        std::thread::sleep(Duration::from_millis(20));
    }

    std::fs::remove_file(&path).expect("unlink fifo");
    write_tokens(&path);

    auth_recovers_after_replace(&store, &path);
}
