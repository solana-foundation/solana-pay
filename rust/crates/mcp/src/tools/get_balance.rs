use rmcp::model::CallToolResult;
use rmcp::schemars;
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Params {
    /// Network to check. Defaults to "mainnet".
    #[schemars(
        description = "Network slug (e.g. \"mainnet\", \"localnet\"). Defaults to mainnet."
    )]
    #[serde(default = "default_network")]
    pub network: String,
}

fn default_network() -> String {
    "mainnet".to_string()
}

pub async fn run(params: Params) -> Result<CallToolResult, rmcp::ErrorData> {
    let network = params.network;
    let accounts = match pay_core::accounts::AccountsFile::load() {
        Ok(accounts) => accounts,
        Err(err) => {
            return Ok(super::tool_error(format!(
                "Failed to load Pay accounts: {err}"
            )));
        }
    };
    let Some((_name, account)) = accounts.account_for_network(&network) else {
        return Ok(super::tool_error(format!(
            "No account configured for {network}. Run `pay setup` first."
        )));
    };

    let Some(pubkey) = account.pubkey.as_deref() else {
        return Ok(super::tool_error(
            "Account has no pubkey. Run `pay setup` again.",
        ));
    };
    let pubkey = pubkey.to_string();
    let rpc_url = if network == "mainnet" {
        pay_core::balance::mainnet_rpc_url()
    } else {
        std::env::var("PAY_RPC_URL").unwrap_or_else(|_| pay_core::balance::mainnet_rpc_url())
    };

    let balances = match pay_core::client::balance::get_stablecoin_balances(&rpc_url, &pubkey).await
    {
        Ok(balances) => balances,
        Err(err) => return Ok(super::tool_error(format!("Balance lookup error: {err}"))),
    };

    let mut lines = vec![];

    for token in &balances.tokens {
        let label = token.symbol_or("unknown");
        lines.push(format!("{label}: {:.2}", token.ui_amount));
    }

    if balances.tokens.is_empty() {
        lines.push("No token balances found.".to_string());
    }

    Ok(CallToolResult::success(vec![
        rmcp::model::ContentBlock::text(lines.join("\n")),
    ]))
}
