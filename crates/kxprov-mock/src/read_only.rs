//! Read-only view of a [`DaemonBackend`] for the call-log read paths (S6 design §3).

use std::sync::Arc;

use kxprov_api::{SmdrPage, SmdrQueryParams, SmdrStatus};

use crate::backend::{DaemonBackend, SmdrSubscription};
use crate::error::BackendError;
use crate::identity::CallerIdentity;
use crate::types::DaemonStatus;

/// Wraps a backend and exposes only methods that cannot reach a PBX write, plan, apply,
/// approval or backup. The inner backend is private, so holders cannot recover it.
#[derive(Clone)]
pub struct ReadOnlyPbxClient {
    inner: Arc<dyn DaemonBackend>,
}

impl ReadOnlyPbxClient {
    pub fn new(backend: Arc<dyn DaemonBackend>) -> Self {
        Self { inner: backend }
    }

    pub async fn status(&self, caller: &CallerIdentity) -> Result<DaemonStatus, BackendError> {
        self.inner.status(caller).await
    }

    pub async fn smdr_query(
        &self,
        caller: &CallerIdentity,
        params: SmdrQueryParams,
    ) -> Result<SmdrPage, BackendError> {
        self.inner.smdr_query(caller, params).await
    }

    pub async fn smdr_status(&self, caller: &CallerIdentity) -> Result<SmdrStatus, BackendError> {
        self.inner.smdr_status(caller).await
    }

    pub async fn smdr_subscribe(
        &self,
        caller: &CallerIdentity,
        since_id: Option<i64>,
    ) -> Result<SmdrSubscription, BackendError> {
        self.inner.smdr_subscribe(caller, since_id).await
    }
}
