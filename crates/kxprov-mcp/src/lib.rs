use std::borrow::Cow;
use std::sync::Arc;

use kxprov_api::{
    ApplyApprovalRequiredResult, CallDirection, JobRef, Profile, QueryLimit, SmdrCursor,
    SmdrQueryParams, TokenId,
};
use kxprov_mock::{diff_hash_from_hex, plan_id_from_hex};
use kxprov_mock::{
    BackendError, CallerIdentity, DaemonBackend, JobId, McpTokenIdentity, PlanChangeRequest,
    ReadFieldsRequest, ScopeSet,
};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, ContentBlock, ErrorCode, ErrorData, ListToolsResult, ServerCapabilities,
    ServerInfo, Tool,
};
use rmcp::service::RequestContext;
use rmcp::tool;
use rmcp::tool_handler;
use rmcp::tool_router;
use rmcp::RoleServer;
use rmcp::ServerHandler;
use schemars::JsonSchema;
use serde::Deserialize;

tokio::task_local! {
    pub static MCP_CALLER: CallerIdentity;
}

#[derive(Clone)]
pub struct KxMcpServer {
    backend: Arc<dyn DaemonBackend>,
    tool_router: ToolRouter<Self>,
}

impl KxMcpServer {
    pub fn new(backend: Arc<dyn DaemonBackend>) -> Self {
        Self {
            backend,
            tool_router: Self::tool_router(),
        }
    }

    /// Tool names registered on this server (for route-table contract tests).
    pub fn registered_tool_names(&self) -> Vec<String> {
        self.tool_router
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect()
    }

    fn caller() -> Result<CallerIdentity, ErrorData> {
        MCP_CALLER.try_with(|c| c.clone()).map_err(|_| ErrorData {
            code: ErrorCode::INVALID_REQUEST,
            message: Cow::Borrowed("missing MCP identity"),
            data: None,
        })
    }

    /// Whether `tools/list` should expose a tool for the given MCP token scopes.
    pub fn tool_visible_for_scopes(tool_name: &str, scopes: &ScopeSet) -> bool {
        match tool_name {
            "apply_plan" | "rollback" => scopes.allows_write(),
            "submit_approval" => scopes.allows_approve(),
            "backup_now" | "plan_change" => scopes.allows_plan(),
            "read_fields" | "list_backups" | "status" => scopes.allows_read(),
            "smdr_query" | "smdr_status" => scopes.allows_call_log(),
            _ => false,
        }
    }

    fn filter_tools_by_scopes(tools: Vec<Tool>, scopes: &ScopeSet) -> Vec<Tool> {
        tools
            .into_iter()
            .filter(|t| Self::tool_visible_for_scopes(t.name.as_ref(), scopes))
            .collect()
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
struct PlanChangeParams {
    table: u8,
    record: u16,
    field: String,
    value: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ReadFieldsParams {
    table: u8,
    record: u16,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ApplyPlanParams {
    plan_id: String,
    diff_hash: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SubmitApprovalParams {
    plan_id: String,
    diff_hash: String,
    profile: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum SmdrDirectionParam {
    Incoming,
    Outgoing,
}

/// Call-log query. Times are Unix milliseconds; the window is `[since_ms, until_ms)`.
#[derive(Debug, Deserialize, JsonSchema)]
struct SmdrQueryToolParams {
    /// Window start; defaults to 24 hours before `until_ms`.
    since_ms: Option<i64>,
    /// Window end (exclusive); defaults to now.
    until_ms: Option<i64>,
    /// Extension label to match exactly.
    ext: Option<String>,
    direction: Option<SmdrDirectionParam>,
    /// Page size, 1 to 100; defaults to 50.
    limit: Option<u16>,
    /// `next` value from the previous page.
    cursor: Option<String>,
}

impl SmdrQueryToolParams {
    fn into_query(self, now_ms: i64) -> Result<SmdrQueryParams, BackendError> {
        let limit = match self.limit {
            Some(n) => QueryLimit::mcp(n).map_err(BackendError::CallLog)?,
            None => QueryLimit::default(),
        };
        let cursor = self
            .cursor
            .as_deref()
            .map(SmdrCursor::decode)
            .transpose()
            .map_err(BackendError::CallLog)?;
        Ok(SmdrQueryParams {
            ext: self.ext,
            direction: self.direction.map(|d| match d {
                SmdrDirectionParam::Incoming => CallDirection::Incoming,
                SmdrDirectionParam::Outgoing => CallDirection::Outgoing,
            }),
            limit,
            cursor,
            ..SmdrQueryParams::with_defaults(self.since_ms, self.until_ms, now_ms)
        })
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
struct RollbackParams {
    job_id: String,
}

#[tool_router]
impl KxMcpServer {
    #[tool(description = "Daemon status")]
    async fn status(&self) -> Result<CallToolResult, ErrorData> {
        let caller = Self::caller()?;
        let status = self.backend.status(&caller).await.map_err(api_err)?;
        Ok(text_json(status))
    }

    #[tool(description = "List backups")]
    async fn list_backups(&self) -> Result<CallToolResult, ErrorData> {
        let caller = Self::caller()?;
        let list = self.backend.list_backups(&caller).await.map_err(api_err)?;
        Ok(text_json(list))
    }

    #[tool(description = "Schedule a backup (plan scope)")]
    async fn backup_now(&self) -> Result<CallToolResult, ErrorData> {
        let caller = Self::caller()?;
        let info = self.backend.backup_now(&caller).await.map_err(api_err)?;
        Ok(text_json(info))
    }

    #[tool(description = "Read table fields")]
    async fn read_fields(
        &self,
        Parameters(params): Parameters<ReadFieldsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = Self::caller()?;
        let resp = self
            .backend
            .read_fields(
                &caller,
                ReadFieldsRequest {
                    table: params.table,
                    record: params.record,
                },
            )
            .await
            .map_err(api_err)?;
        Ok(text_json(resp))
    }

    #[tool(description = "Plan a dry-run change")]
    async fn plan_change(
        &self,
        Parameters(params): Parameters<PlanChangeParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = Self::caller()?;
        let summary = self
            .backend
            .plan_change(
                &caller,
                PlanChangeRequest {
                    table: params.table,
                    record: params.record,
                    field: params.field,
                    new_value: params.value,
                    base_bytes: Vec::new(),
                    new_bytes: Vec::new(),
                },
            )
            .await
            .map_err(api_err)?;
        Ok(text_json(summary))
    }

    #[tool(description = "Apply a plan (prod profile requires MCP approval)")]
    async fn apply_plan(
        &self,
        Parameters(params): Parameters<ApplyPlanParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = Self::caller()?;
        let plan_id = plan_id_from_hex(&params.plan_id).map_err(api_err)?;
        let diff_hash = diff_hash_from_hex(&params.diff_hash).map_err(api_err)?;
        match self.backend.apply_plan(&caller, plan_id, diff_hash).await {
            Ok(job) => Ok(text_json(JobRef {
                job_id: job.job_id.0,
            })),
            Err(BackendError::ApprovalRequired(body)) => {
                Ok(text_json(ApplyApprovalRequiredResult {
                    plan_id: body.plan_id,
                    diff_hash: body.diff_hash,
                    status: body.status,
                }))
            }
            Err(e) => Err(api_err(e)),
        }
    }

    #[tool(
        description = "Submit approval (approve scope; plan id or 8-hex prefix, diff_hash, profile)"
    )]
    async fn submit_approval(
        &self,
        Parameters(params): Parameters<SubmitApprovalParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = Self::caller()?;
        let diff_hash = diff_hash_from_hex(&params.diff_hash).map_err(api_err)?;
        let profile = parse_profile(&params.profile).map_err(api_err)?;
        let approval = self
            .backend
            .submit_approval(&caller, &params.plan_id, diff_hash, profile)
            .await
            .map_err(api_err)?;
        Ok(text_json(approval))
    }

    #[tool(description = "Rollback a job (write scope)")]
    async fn rollback(
        &self,
        Parameters(params): Parameters<RollbackParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = Self::caller()?;
        let job = self
            .backend
            .rollback(&caller, JobId(params.job_id))
            .await
            .map_err(api_err)?;
        Ok(text_json(job))
    }

    #[tool(
        description = "Read stored phone call records (call-log scope; read-only, newest first, at most 31 days and 100 rows per call)"
    )]
    async fn smdr_query(
        &self,
        Parameters(params): Parameters<SmdrQueryToolParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = Self::caller()?;
        if !caller.scopes().allows_call_log() {
            return Err(api_err(BackendError::ForbiddenScope));
        }
        let now_ms =
            i64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
                .map_err(|_| api_err(BackendError::BadRequest("clock")))?;
        let query = params.into_query(now_ms).map_err(api_err)?;
        let page = kxprov_mock::ReadOnlyPbxClient::new(self.backend.clone())
            .smdr_query(&caller, query)
            .await
            .map_err(api_err)?;
        Ok(text_json(page))
    }

    #[tool(
        description = "Call-log reader status: whether the port is listening, paused for a programming session, disabled or down, plus counters (call-log scope; read-only)"
    )]
    async fn smdr_status(&self) -> Result<CallToolResult, ErrorData> {
        let caller = Self::caller()?;
        if !caller.scopes().allows_call_log() {
            return Err(api_err(BackendError::ForbiddenScope));
        }
        let status = kxprov_mock::ReadOnlyPbxClient::new(self.backend.clone())
            .smdr_status(&caller)
            .await
            .map_err(api_err)?;
        Ok(text_json(status))
    }
}

fn text_json<T: serde::Serialize>(value: T) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string(&value).unwrap_or_else(|_| "{}".into()),
    )])
}

fn parse_profile(raw: &str) -> Result<Profile, BackendError> {
    serde_json::from_value(serde_json::Value::String(raw.trim().to_string()))
        .map_err(|_| BackendError::BadRequest("profile"))
}

fn api_err(err: BackendError) -> ErrorData {
    ErrorData {
        code: ErrorCode::INTERNAL_ERROR,
        message: Cow::Owned(err.to_string()),
        data: None,
    }
}

#[tool_handler]
impl ServerHandler for KxMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("KX-TD1232 provisioning MCP (simulator)")
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let caller = Self::caller().unwrap_or_else(|_| {
            CallerIdentity::Mcp(McpTokenIdentity {
                token_id: TokenId("unknown".into()),
                agent_name: "unknown".into(),
                scopes: ScopeSet::empty(),
                bearer: String::new(),
            })
        });
        let tools = Self::filter_tools_by_scopes(self.tool_router.list_all(), &caller.scopes());
        Ok(ListToolsResult {
            tools,
            next_cursor: None,
            meta: None,
        })
    }
}

#[cfg(test)]
mod smdr_tool_tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test setup failures should abort the test"
    )]
    use super::*;
    use kxprov_api::{Scope, SmdrCallView, SmdrPage};
    use kxprov_mock::{scopes_for_role, MockDaemon};

    fn caller(scopes: ScopeSet) -> CallerIdentity {
        CallerIdentity::Mcp(McpTokenIdentity {
            token_id: TokenId("bots".into()),
            agent_name: "bots".into(),
            scopes,
            bearer: String::new(),
        })
    }

    fn params(limit: Option<u16>, cursor: Option<String>) -> SmdrQueryToolParams {
        SmdrQueryToolParams {
            since_ms: Some(0),
            until_ms: Some(1_000_000),
            ext: None,
            direction: None,
            limit,
            cursor,
        }
    }

    async fn server_with_calls(n: i64) -> KxMcpServer {
        let mock = MockDaemon::new();
        for i in 1..=n {
            mock.test_add_call(
                i * 1000,
                SmdrCallView {
                    id: i,
                    rx_ts_utc: format!("1970-01-01T00:00:{:02}.000Z", i % 60),
                    pbx_local: String::new(),
                    ext: "101".into(),
                    co: "01".into(),
                    direction: CallDirection::Incoming,
                    number: format!("555{i:04}"),
                    cid_text: None,
                    ring_s: None,
                    duration_s: Some(10),
                    acc: None,
                },
            )
            .await;
        }
        KxMcpServer::new(Arc::new(mock))
    }

    fn page(r: CallToolResult) -> SmdrPage {
        let text = serde_json::to_value(&r.content).unwrap()[0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn tool_is_listed_only_with_call_log() {
        let bots = scopes_for_role("bots");
        assert!(KxMcpServer::tool_visible_for_scopes("smdr_query", &bots));
        for role in ["tester", "communications", "approver"] {
            assert!(
                !KxMcpServer::tool_visible_for_scopes("smdr_query", &scopes_for_role(role)),
                "{role}"
            );
        }
        let read_only = ScopeSet::empty().with(Scope::Read);
        assert!(!KxMcpServer::tool_visible_for_scopes(
            "smdr_query",
            &read_only
        ));
        for write_tool in [
            "apply_plan",
            "plan_change",
            "backup_now",
            "submit_approval",
            "rollback",
        ] {
            assert!(
                !KxMcpServer::tool_visible_for_scopes(write_tool, &bots),
                "{write_tool}"
            );
        }
    }

    #[tokio::test]
    async fn call_without_call_log_is_refused() {
        let server = server_with_calls(3).await;
        let r = MCP_CALLER
            .scope(
                caller(ScopeSet::empty().with(Scope::Read).with(Scope::Plan)),
                server.smdr_query(Parameters(params(None, None))),
            )
            .await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn mcp_caps_the_page_at_100_and_pages_by_cursor() {
        let server = server_with_calls(5).await;
        let who = caller(scopes_for_role("bots"));
        let over = MCP_CALLER
            .scope(
                who.clone(),
                server.smdr_query(Parameters(params(Some(101), None))),
            )
            .await;
        assert!(over.is_err());
        let first = page(
            MCP_CALLER
                .scope(
                    who.clone(),
                    server.smdr_query(Parameters(params(Some(2), None))),
                )
                .await
                .unwrap(),
        );
        let ids: Vec<i64> = first.calls.iter().map(|c| c.id).collect();
        assert_eq!(ids, [5, 4]);
        let cursor = first.next.unwrap().encode();
        let second = page(
            MCP_CALLER
                .scope(
                    who.clone(),
                    server.smdr_query(Parameters(params(Some(2), Some(cursor)))),
                )
                .await
                .unwrap(),
        );
        assert_eq!(
            second.calls.iter().map(|c| c.id).collect::<Vec<_>>(),
            [3, 2]
        );
        let bad = MCP_CALLER
            .scope(
                who,
                server.smdr_query(Parameters(params(None, Some("zz".into())))),
            )
            .await;
        assert!(bad.is_err());
    }
}
