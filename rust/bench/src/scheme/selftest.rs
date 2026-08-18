//! Self-test scheme — the generator/proxy ceiling check.
//!
//! No on-chain work at all: no funding, no signing, no settlement. It just
//! fires plain requests at a **free** proxy path (which still traverses the
//! payment middleware's passthrough). Use it to answer "how many concurrent
//! users / requests-per-second can the bench drive and the proxy serve?" —
//! decoupled from Solana entirely. This is the honest way to see large user
//! counts before the on-chain schemes (charge/session) bound throughput.

use anyhow::Result;
use async_trait::async_trait;

use super::{
    BenchScheme, Endpoint, Load, PerUserFunding, PreparedRequest, RequestSource, ResolvedPrice,
    UserCtx, UserSetup,
};

pub struct SelfTest;

#[async_trait]
impl BenchScheme for SelfTest {
    fn name(&self) -> &'static str {
        "self_test"
    }

    async fn resolve(
        &self,
        _http: &reqwest::Client,
        _endpoint: &Endpoint,
        _host_override: Option<&str>,
    ) -> Result<ResolvedPrice> {
        // No price to learn — the target is a free path.
        Ok(ResolvedPrice {
            amount_base: 0,
            currency: "none".into(),
            mint: None,
            recipient: String::new(),
            network: "localnet".into(),
            decimals: 0,
            fee_sponsored: false,
        })
    }

    fn funding_plan(&self, _load: &Load, _price: &ResolvedPrice) -> PerUserFunding {
        PerUserFunding::default() // zero — the engine's funder is a no-op here
    }

    async fn provision_user(&self, _ctx: &UserCtx) -> Result<UserSetup> {
        Ok(UserSetup::default())
    }

    async fn request_source(
        &self,
        ctx: &UserCtx,
        _setup: &UserSetup,
    ) -> Result<Box<dyn RequestSource>> {
        let mut headers = Vec::new();
        if let Some(host) = &ctx.host_override {
            headers.push(("host".to_string(), host.clone()));
        }
        Ok(Box::new(SelfTestSource {
            index: ctx.index,
            method: ctx.endpoint.method.clone(),
            url: ctx.endpoint.url.clone(),
            headers,
            body: ctx.endpoint.body.clone(),
        }))
    }

    async fn settle_and_close(&self, _ctx: &UserCtx, _setup: &UserSetup) -> Result<()> {
        Ok(())
    }
}

struct SelfTestSource {
    index: u32,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: String,
}

#[async_trait]
impl RequestSource for SelfTestSource {
    fn user_index(&self) -> u32 {
        self.index
    }

    async fn next_request(&mut self) -> Result<PreparedRequest> {
        Ok(PreparedRequest {
            method: self.method.clone(),
            url: self.url.clone(),
            headers: self.headers.clone(),
            body: self.body.clone(),
            logical_payment: false,
        })
    }
}
