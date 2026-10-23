//! FIFO `tokens.json` reload: one probe thread, fast fail-closed auth under hang.

#![allow(clippy::unwrap_used)]
#![cfg(unix)]

use kxprov_api::Scope;
use kxprovd::tokens::{TokenError, TokenStore};
use serial_test::serial;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn write_tokens(path: &std::path::Path) {
    let file = kxprovd::test_util::default_tokens_file();
    TokenStore::write_test_file(path, &file).expect("write tokens");
}

#[test]
#[serial]
fn fifo_tokens_single_probe_thread_fast_fail_and_recovery() {
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
        max_live.load(Ordering::Relaxed) <= 1,
        "live probe threads peaked at {}",
        max_live.load(Ordering::Relaxed)
    );
    assert!(
        fast_denies.load(Ordering::Relaxed) > 0,
        "expected fast StoreUnavailable denials while probe was outstanding"
    );
    assert_eq!(
        slow_calls.load(Ordering::Relaxed),
        0,
        "calls after the first probe must not wait on the reload window"
    );

    {
        use std::io::Write;
        let file = kxprovd::test_util::default_tokens_file();
        let bytes = serde_json::to_vec_pretty(&file).expect("json");
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open fifo for write to unblock probe");
        writer
            .write_all(bytes.as_slice())
            .expect("feed valid tokens through fifo");
    }

    let drain_deadline = Instant::now() + Duration::from_secs(5);
    while store.live_disk_probe_threads_for_test() > 0 {
        assert!(
            Instant::now() < drain_deadline,
            "probe thread did not finish after FIFO fed"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    std::fs::remove_file(&path).expect("remove fifo");
    write_tokens(&path);

    store
        .verify_bearer(kxprovd::test_util::WRITER_SECRET, 0, Scope::Plan)
        .expect("auth recovers after valid tokens.json restored");
    assert_eq!(store.live_disk_probe_threads_for_test(), 0);
}
