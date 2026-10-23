//! Simulator apply with per-block read-back (Tester: replies have no sequence number).

use crate::backup::BackupStore;
use crate::config::Config;
use crate::locked::LockedStore;
use crate::plan_store::PlanStore;
use crate::time::now_ms;
use crate::transport::{open, AnyTransport};
use kxprov_api::Profile;
use kxtd1232::frame::Access;
use kxtd1232::plan::ChunkWrite;
use kxtd1232::{Client, Timing};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApplyError {
    #[error("protocol: {0}")]
    Protocol(#[from] kxtd1232::Error),
    #[error("plan: {0}")]
    Plan(#[from] crate::plan_store::PlanError),
    #[error("backup: {0}")]
    Backup(#[from] crate::backup::BackupError),
    #[error("no verified backup; header tail unavailable")]
    NoBackup,
    #[error("read-back mismatch at table {0:#x} record {1} word {2}")]
    ReadBackMismatch(u8, u16, u16),
    #[error("simulator-only")]
    NotSim,
    #[error("transport: {0}")]
    Transport(String),
}

pub fn run_apply(
    config: &Config,
    profile: Profile,
    plans: &PlanStore,
    backups: &BackupStore,
    plan_id: &kxprov_api::PlanId,
    diff_hash: &kxprov_api::DiffHash,
    token: &kxprov_api::TokenId,
) -> Result<usize, ApplyError> {
    let sim_transport = config.transport == crate::config::TransportKind::Sim;
    let sim_profile = matches!(profile, Profile::Sim | Profile::Test);
    if !sim_profile || !sim_transport {
        return Err(ApplyError::NotSim);
    }
    let now = now_ms();
    let rec = plans.verify_for_apply(plan_id, diff_hash, profile, token, now)?;
    backups.require_backup_for_write()?;
    let writes: Vec<ChunkWrite> = rec
        .writes
        .iter()
        .map(|w| ChunkWrite {
            table: w.table,
            record: w.record,
            word: w.word,
            base: w.base.clone(),
            new: w.new.clone(),
        })
        .collect();
    let pwd = config.password.clone();
    let transport = open(config.transport, &config.serial_device).map_err(ApplyError::Transport)?;
    let mut client = Client::with(transport, Access::ReadWrite, Timing::default());
    client.login(&pwd)?;
    for w in &writes {
        apply_one_write(&mut client, w)?;
    }
    let _ = client.end_binary();
    Ok(writes.len())
}

fn apply_one_write(client: &mut Client<AnyTransport>, w: &ChunkWrite) -> Result<(), ApplyError> {
    let nwords = (w.new.len() / 2) as u8;
    client.write(w.table, w.record, w.word, &w.new)?;
    let got = client.read(w.table, w.record, w.word, nwords)?;
    if got != w.new {
        return Err(ApplyError::ReadBackMismatch(w.table, w.record, w.word));
    }
    Ok(())
}

pub fn lock_on_apply_failure(locked: &LockedStore, reason: &str, job_id: &str) {
    let _ = locked.set_locked(reason, Some(job_id), now_ms());
}
