//! Named discards for kxprovd (coding rule: every intentional drop states its reason).

use std::path::Path;
use std::sync::mpsc::SyncSender;

use tokio::sync::oneshot;

use crate::apply::lock_on_apply_failure;
use crate::audit::{AuditEntry, AuditLog};
use crate::journal::{Journal, JournalEntry};
use crate::locked::LockedStore;
use crate::queue::JobOutcome;
use crate::sim_mark::SimMarkStore;
use crate::transition::TransitionBlockStore;
use kxtd1232::Client;

/// Process id still uniquifies the temp path if getrandom fails.
pub fn fill_atomic_temp_nonce(out: &mut [u8; 8]) {
    let _ = getrandom::fill(out);
}

/// Parent-directory fsync after rename is best-effort on some filesystems.
pub fn sync_opened_parent_dir_best_effort(dir: &std::fs::File) {
    let _ = dir.sync_all();
}

/// After successful table I/O the port lease ends on drop; END BINARY is session hygiene.
pub fn end_kxtd_session_binary<T: kxtd1232::Transport>(client: &mut Client<T>) {
    let _ = client.end_binary();
}

/// Append-only audit; the caller already chose the operational outcome.
pub fn audit_append_nonblocking(audit: &AuditLog, entry: AuditEntry) {
    let _ = audit.append(&entry);
}

/// Persist `alert_sent` after the warn line; status polling stays best-effort if disk fails.
pub fn mark_locked_alert_sent_best_effort(locked: &LockedStore) {
    let _ = locked.mark_alert_sent();
}

/// Live verify succeeded; a stale block file is harmless but clear is attempted.
pub fn transition_clear_after_verified_production(store: &TransitionBlockStore) {
    let _ = store.clear();
}

/// The HTTP client may disconnect before the worker finishes the job.
pub fn send_job_outcome_best_effort(tx: oneshot::Sender<JobOutcome>, outcome: JobOutcome) {
    let _ = tx.send(outcome);
}

/// LOCKED is recorded when apply post-steps fail; the job is already returning an error.
pub fn lock_on_apply_failure_best_effort(locked: &LockedStore, reason: &str, job_id: &str) {
    if let Err(e) = lock_on_apply_failure(locked, reason, job_id) {
        tracing::error!(
            reason = %reason,
            job_id,
            error = %e,
            "failed to persist LOCKED after apply post-step failure"
        );
    }
}

/// Journal replay locks after an incomplete apply; serve must still start if lock write fails.
pub fn lock_after_journal_recovered_apply(locked: &LockedStore, job_id: &str, now_ms: u64) {
    if let Err(e) = locked.set_locked(
        "recovered incomplete apply after restart",
        Some(job_id),
        now_ms,
    ) {
        tracing::error!(
            job_id,
            error = %e,
            "failed to persist LOCKED after journal recovered incomplete apply"
        );
    }
}

/// Backup proceeds when journal append fails; replay may not see this operation.
pub fn journal_append_best_effort(journal: &Journal, entry: JournalEntry) {
    let _ = journal.append(&entry);
}

/// Truncate after a successful backup; a full journal only affects replay diagnostics.
pub fn journal_truncate_best_effort(journal: &Journal) {
    let _ = journal.truncate();
}

/// Remove leftover paths when the primary error is already returned.
pub fn remove_file_best_effort(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// Drop stale simulator mark files before serving; failure leaves a harmless marker.
pub fn sim_mark_clear_stale_on_boot(store: &SimMarkStore) {
    let _ = store.clear_if_stale();
}

/// Startup failed before ready; the parent may already have timed out.
pub fn daemon_ready_send_failure(tx: &SyncSender<Result<(), String>>, err: String) {
    let _ = tx.send(Err(err));
}

/// Transition alert fired; persisting `alert_sent` avoids duplicate warns only.
pub fn transition_alert_sent_persist_best_effort(path: &Path, bytes: &[u8]) {
    let _ = std::fs::write(path, bytes);
}

/// Prune keeps the newest backups; missing files are already gone.
pub fn remove_pruned_backup_pair_best_effort(dbh: &Path, meta: &Path) {
    let _ = std::fs::remove_file(dbh);
    let _ = std::fs::remove_file(meta);
}

/// Drop closes the fifo read fd; EINTR/EBADF on close are harmless during probe teardown.
pub fn close_fifo_read_fd_best_effort(fd: nix::libc::c_int) {
    let _ = nix::unistd::close(fd);
}

/// Stale or wrong-build sim marks are removed best-effort during read/clear.
pub fn remove_stale_sim_mark_best_effort(path: &Path) {
    let _ = std::fs::remove_file(path);
}
