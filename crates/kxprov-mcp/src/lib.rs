use std::borrow::Cow;
use std::sync::Arc;

use kxprov_api::{ApplyApprovalRequiredResult, JobRef, Profile, TokenId};
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
