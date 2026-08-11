//! MCP server — thin dispatch layer.
//!
//! Each tool's logic and params live in `tools/<name>.rs`.

use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ServerHandler, tool, tool_router};

use crate::tools;

pub struct PayMcp {
    #[allow(dead_code)]
    tool_router: rmcp::handler::server::router::tool::ToolRouter<Self>,
    capability_mrtr: tools::request_capability::MrtrState,
    payment_sessions: pay_core::session_manager::SessionManager,
}

impl Default for PayMcp {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
impl PayMcp {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
            capability_mrtr: tools::request_capability::MrtrState::default(),
            payment_sessions: pay_core::session_manager::SessionManager::default(),
        }
    }

    #[tool(
        description = r#"Make an HTTP request through Pay with 402 Payment Required handling.

Use this as the primary HTTP tool for Pay gateway URLs and for any URL that
returns HTTP 402. The tool prepares MPP, x402, or SIWX credentials, asks for
local wallet approval when payment is required, then retries the original
request with the proof. The active Pay account only needs supported
stablecoins such as USDC, USDT, PYUSD, CASH, or USDG; it does not need SOL for network fees.
Server-side fee payers handle transaction fees and setup costs. Copy URLs
returned by `search_catalog` or `get_catalog_entry` exactly; do not replace
them with upstream API hosts.

`body` may be a string or a JSON value. JSON values are serialized before the
request and `Content-Type: application/json` is added when no content type is
provided. For a local binary or large body, pass `body_file`. Its path must be
inside an MCP client-declared filesystem root; Pay asks the user to approve the
file, size, method, and destination before reading it. Pay snapshots the file
once, does not follow redirects, and reuses those exact bytes for a 402 retry.

For multipart local uploads, use one filesystem-authorized command:
`pay fetch <URL> --method <METHOD> --form NAME=VALUE --form-file NAME=PATH`.

For URLs that match a cached Pay catalog endpoint with an inlined OpenAPI
document, Pay validates the method and JSON request body locally before sending.
If required fields or types are wrong, the tool returns a clear validation error
and does not submit the request or payment.
"#
    )]
    async fn curl(
        &self,
        Parameters(params): Parameters<tools::curl::Params>,
        peer: rmcp::Peer<rmcp::service::RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        tools::curl::run(params, peer, self.payment_sessions.clone()).await
    }

    #[tool(
        description = r#"Search paid API services for a user task and return ranked candidates with endpoint context.

Use this for actionable Pay-owned tasks after the user asks to do something,
such as "search Instagram influencers in Paris" or "run SQL over public crypto
datasets". Do not use this as the first tool for capability questions like
"can I use Pay to X?", "can I order X with Pay?", "does Pay support X?", or
"what can Pay do?". For those, call `list_catalog` first because search ranks a
task and can miss adjacent catalog providers. The response is ranked and
includes reasons, endpoint/pricing candidates, tie-breaker guidance, call-plan
fields, and the next provider-selection step. Select an endpoint only when it
clearly matches the task; otherwise inspect one likely provider with
`get_catalog_entry` or ask the user.

On a measured miss (no candidate clearly fits — weak keyword matches may still
be listed), this same tool call enters a resumable MRTR flow: one user prompt,
then local-model refinement with read-only catalog research, strict validation,
and quote-ready studio submission. Do not pre-ask in chat and do not call
`request_capability` afterward for the same query. If the MCP client cannot run
MRTR, the ordinary search result explains the unsupported flow and nothing is
sent to a studio.
"#
    )]
    async fn search_catalog(
        &self,
        Parameters(params): Parameters<tools::search_catalog::Params>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        tools::search_catalog::run(params).await
    }

    #[tool(description = r#"List all available Pay APIs/skills.

Use this first for Pay capability and feasibility questions: "can I use Pay to
X?", "can I order X with Pay?", "does Pay support X?", "what can Pay do?", or
similar. Never answer "no" about Pay capabilities from memory or from a
`search_catalog` result alone; inspect the full catalog with this tool first.
Returns a compact category-grouped catalog by default to keep MCP hosts
responsive. Set `include_details` only when the user needs the expanded raw
service list with use cases. For actionable execution after capability is
established, call `search_catalog` with the user's task. When the user asks what
Pay can do, present the catalog grouped by category so they can scan available
APIs/skills.

If the catalog does NOT cover the user's need, do not stop at "no": call
`search_catalog` with the user's real task. On a miss it prompts the user
itself (never pre-ask in chat) with an offer to have the capability built
by the studio registry — a gap in the catalog is an opportunity for the
user to get an API built, published, and monetized under them, so present
it that way instead of dead-ending at "no".
"#)]
    async fn list_catalog(
        &self,
        Parameters(params): Parameters<tools::list_catalog::Params>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        tools::list_catalog::run(params).await
    }

    #[tool(
        description = r#"Get full details for a specific API service by its fqn.

Returns endpoints (each with a complete `url` for the `curl` tool),
usage notes, pricing info, sandbox/production URLs, and a next-step hint. Call
this after picking a service from `search_catalog` when endpoint candidates are
not enough to make a precise paid-call plan.
"#
    )]
    async fn get_catalog_entry(
        &self,
        Parameters(params): Parameters<tools::get_catalog_entry::Params>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        tools::get_catalog_entry::run(params).await
    }

    #[tool(description = r#"Get the balance of the active pay account.

Returns stablecoin balances for the currently configured account. Paid API
calls spend supported stablecoins such as USDC, USDT, PYUSD, CASH, or USDG; the account does
not need SOL for network fees because server-side fee payers handle fees and
setup costs. Use this to check available funds before making paid API calls.
"#)]
    async fn get_balance(
        &self,
        Parameters(params): Parameters<tools::get_balance::Params>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        tools::get_balance::run(params).await
    }

    #[tool(
        description = r#"Generate a top-up QR code PNG for the user's Pay account.

Use this when the user asks to top up, fund, add money, deposit stablecoins, or
create a QR code for adding funds to Pay. The user must choose the top-up method:
`mobile_wallet` for a Solana Pay USDC QR code, or `onramp` for a provider QR
code. When `method` is `onramp`, the user must also specify the provider
(`coinbase`, `paypal`, or `venmo`). This tool does not spend funds or initiate
a purchase; it only renders the QR PNG and returns the funding address.
"#
    )]
    async fn topup(
        &self,
        Parameters(params): Parameters<tools::topup::Params>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        tools::topup::run(params).await
    }

    #[tool(description = r#"Create or validate a pay-skills provider listing.

Use this when a developer wants to publish a payment-gated API in
https://github.com/solana-foundation/pay-skills. Pass the complete provider
markdown file as `content`: YAML frontmatter between `---` delimiters followed
by optional execution notes. The tool validates required metadata, endpoint
shape, URL safety, pricing precision, and paid-endpoint expectations.

Before calling, inspect real code, OpenAPI specs, deployed routes, or
`pay gate api` YAML. Do not invent endpoints, prices, supported networks,
or payment protocols. If runtime YAML exists, use `pay skills provider sync`
as a starting point, then validate the generated markdown with this tool.

For detailed authoring guidance, use the Pay skill reference
`references/monetize-api.md`.
"#)]
    async fn create_skill(
        &self,
        Parameters(params): Parameters<tools::create_skill::Params>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        tools::create_skill::run(params).await
    }

    #[tool(
        description = r#"Ask the studio registry to build a capability Pay doesn't have yet.

`search_catalog` starts this automatically on a measured miss; do not call it
again for the same query. In every other uncovered case, call it directly:
search returned weak matches that do not perform the task, `list_catalog`
showed nothing fitting, or the user asks to have something built. NEVER pre-ask
for permission in chat. This one resumable MCP call owns the consent prompt,
local-model research with read-only Pay catalog tools, strict quote-ready brief
validation, and studio submission. There is no second tool call for the model
to remember. Calling on a suspected miss is safe because declining costs
nothing and submits nothing; invalid or incomplete refinement fails closed.
Frame the offer as unmet demand the user can own and monetize, not paperwork.
The request is attributed to the user's Pay wallet and reported as quoted,
pending, or failed. This never spends funds; accepting and funding a quote is
a separate step. Requires MCP 2026-07-28 MRTR, form elicitation, and
sampling-with-tools.
"#
    )]
    async fn request_capability(
        &self,
        Parameters(_params): Parameters<tools::request_capability::Params>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(tools::tool_error(
            "request_capability requires MCP 2026-07-28 multi-round-trip request support",
        ))
    }
}

impl ServerHandler for PayMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2026_07_28)
            .with_instructions(pay_core::instructions::INSTRUCTIONS)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, rmcp::ErrorData> {
        let capability_flow = request.name == "request_capability"
            || (request.name == "search_catalog" && request.request_state.is_some());
        if capability_flow {
            let supported = supports_capability_mrtr(&context);
            if !supported {
                return Ok(tools::tool_error(
                    "request_capability requires MCP 2026-07-28 with form elicitation and sampling-with-tools. Nothing was sent to a studio.",
                )
                .into());
            }
            return tools::request_capability::run_mrtr(
                request,
                context.peer,
                &self.capability_mrtr,
            )
            .await;
        }

        if request.name == "search_catalog" {
            let params = match serde_json::from_value::<tools::search_catalog::Params>(
                serde_json::Value::Object(request.arguments.clone().unwrap_or_default()),
            ) {
                Ok(params) => params,
                Err(error) => {
                    return Ok(tools::tool_error(format!(
                        "Invalid search_catalog parameters: {error}"
                    ))
                    .into());
                }
            };
            let (result, miss) = tools::search_catalog::run_with_miss(params).await?;
            if !miss {
                return Ok(result.into());
            }
            let supported = supports_capability_mrtr(&context);
            if !supported {
                return Ok(result.into());
            }
            return tools::request_capability::run_mrtr(
                request,
                context.peer,
                &self.capability_mrtr,
            )
            .await;
        }

        self.tool_router
            .call(ToolCallContext::new(self, request, context))
            .await
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        Ok(ListToolsResult::with_all_items(self.tool_router.list_all()))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tool_router.get(name).cloned()
    }
}

fn supports_capability_mrtr(context: &RequestContext<RoleServer>) -> bool {
    context.protocol_version() == Some(ProtocolVersion::V_2026_07_28)
        && context.client_capabilities().is_some_and(|capabilities| {
            capabilities
                .elicitation
                .is_some_and(|elicitation| elicitation.form.is_some())
                && capabilities
                    .sampling
                    .is_some_and(|sampling| sampling.tools.is_some())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::ServerHandler;

    #[test]
    fn server_info_has_instructions() {
        let mcp = PayMcp::new();
        let info = mcp.get_info();
        assert!(info.instructions.is_some());
        let instructions = info.instructions.unwrap();
        assert!(instructions.contains("Tool Routing"));
        assert!(instructions.contains("search_catalog({query})"));
        assert!(instructions.contains("Provider Selection Rules"));
        assert!(instructions.contains("Failure Recipes"));
        assert!(instructions.contains("402"));
        assert!(instructions.contains("Never answer \"Can pay do X\" from memory"));
    }

    #[test]
    fn server_info_protocol_version() {
        let mcp = PayMcp::new();
        let info = mcp.get_info();
        assert_eq!(info.protocol_version, ProtocolVersion::V_2026_07_28);
    }

    #[test]
    fn tool_descriptions_keep_provider_selection_pay_first() {
        let source = include_str!("server.rs");
        assert!(source.contains("call `list_catalog` first"));
        assert!(source.contains("Use this first for Pay capability and feasibility questions"));
        assert!(source.contains("Never answer \"no\" about Pay capabilities"));
        assert!(source.contains("present the catalog grouped"));
        assert!(source.contains("Generate a top-up QR code PNG"));
        assert!(source.contains("must also specify the provider"));
        assert!(source.contains("tie-breaker guidance"));
        assert!(source.contains("local wallet approval"));
        assert!(source.contains("does not need SOL for network fees"));
        assert!(source.contains("Server-side fee payers handle"));
        assert!(!source.contains(concat!("Bash tool", " with curl/wget")));
    }
}
