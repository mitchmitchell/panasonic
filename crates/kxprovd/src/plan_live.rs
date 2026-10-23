//! Live PBX base re-read for DiffHash verification (v2.6 F1).

use crate::config::Config;
use crate::plan_store::{diff_hash_with_live_table, PlanError, PlanStore};
use crate::transport::open;
use kxprov_api::{DiffHash, PlanId, Profile};
use kxtd1232::Client;

pub fn verify_live_diff_hash(
    config: &Config,
    profile: Profile,
    plans: &PlanStore,
    plan_id: &PlanId,
    expected: &DiffHash,
) -> Result<(), PlanError> {
    let rec = plans.get(plan_id)?;
    if rec.diff_hash != *expected {
        return Err(PlanError::DiffMismatch);
    }
    let transport = open(config).map_err(|_| PlanError::NotFound)?;
    let mut client = Client::with(transport, kxtd1232::frame::Access::ReadOnly, config.timing);
    client
        .login(&config.password)
        .map_err(|_| PlanError::NotFound)?;
    let table = client
        .read_table(rec.table)
        .map_err(|_| PlanError::NotFound)?;
    let _ = client.end_binary();
    let live = diff_hash_with_live_table(profile, &rec, &table)?;
    if live != rec.diff_hash {
        return Err(PlanError::DiffMismatch);
    }
    Ok(())
}
