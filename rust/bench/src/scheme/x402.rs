//! x402 `exact` scheme — fixed-amount per-request payment.
//!
//! Prepare builds a signed payment header per request
//! (`pay_core::client::x402::build_payment`); settlement is server-side/deferred,
//! so the request path is signature-verify only (a secondary high-RPS path).
//!
//! Implemented in milestone M5; trait surface in place now. Note: `up_to` is
//! server-side volume-tier *pricing* (`PriceTier.up_to`), not a wire scheme —
//! exercised via tiered endpoints, not a separate impl.

use anyhow::{Result, bail};
use async_trait::async_trait;

use super::{
    BenchScheme, Endpoint, Load, PerUserFunding, PreparedRequest, ResolvedPrice, UserCtx, UserSetup,
};

pub struct X402Exact;

#[async_trait]
impl BenchScheme for X402Exact {
    fn name(&self) -> &'static str {
        "x402_exact"
    }

    async fn resolve(
        &self,
        _http: &reqwest::Client,
        _endpoint: &Endpoint,
        _host_override: Option<&str>,
    ) -> Result<ResolvedPrice> {
        bail!("x402_exact not implemented yet (M5): parse x402 PAYMENT-REQUIRED challenge")
    }

    fn funding_plan(&self, _load: &Load, _price: &ResolvedPrice) -> PerUserFunding {
        PerUserFunding::default()
    }

    async fn provision_user(&self, _ctx: &UserCtx) -> Result<UserSetup> {
        Ok(UserSetup::default())
    }

    async fn prepare(
        &self,
        _ctx: &UserCtx,
        _setup: &UserSetup,
        _n: usize,
    ) -> Result<Vec<PreparedRequest>> {
        bail!("x402_exact not implemented yet (M5): build_payment per request")
    }

    async fn settle_and_close(&self, _ctx: &UserCtx, _setup: &UserSetup) -> Result<()> {
        Ok(())
    }
}
