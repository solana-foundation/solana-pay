//! Reusable client-side MPP session state.
//!
//! Frontends keep transport concerns, while this module owns session scoping,
//! serialization, credential adoption, and operator-session preparation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use pay_kit::mpp::{PaymentChallenge, SessionRequest, SessionVoucherSigner};
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::accounts::AccountsStore;
use crate::client::session;
use crate::{Error, Result};

/// Identity of one reusable client session.
///
/// Provider gateways are isolated by origin. Network and account overrides
/// are part of the key so changing either cannot reuse another payer's proof.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SessionKey {
    origin: String,
    network: Option<String>,
    account: Option<String>,
}

impl SessionKey {
    pub fn for_resource(
        resource_url: &str,
        network: Option<&str>,
        account: Option<&str>,
    ) -> Result<Self> {
        Ok(Self {
            origin: session::canonical_session_origin(resource_url)?,
            network: network.map(str::to_string),
            account: account.map(str::to_string),
        })
    }
}

/// One serialized session credential slot.
#[derive(Clone, Default)]
pub struct SessionSlot {
    credential: Arc<Mutex<Option<String>>>,
}

impl SessionSlot {
    pub async fn acquire(&self) -> SessionLease {
        SessionLease {
            credential: self.credential.clone().lock_owned().await,
        }
    }

    /// Acquire from a blocking worker thread.
    ///
    /// This must not run on a Tokio async worker. MCP curl calls it inside its
    /// existing `spawn_blocking` payment worker.
    pub fn blocking_acquire(&self) -> SessionLease {
        SessionLease {
            credential: self.credential.clone().blocking_lock_owned(),
        }
    }
}

/// Exclusive access to one provider session for the duration of a request.
///
/// Holding the lease until the response body is received prevents concurrent
/// requests from reserving the same remaining channel capacity.
pub struct SessionLease {
    credential: OwnedMutexGuard<Option<String>>,
}

impl SessionLease {
    pub fn authorization(&self) -> Option<&str> {
        self.credential.as_deref()
    }

    /// Adopt a new reusable credential after its open request succeeds.
    pub fn adopt(&mut self, authorization: String) {
        *self.credential = Some(authorization);
    }

    /// Forget a credential that the gateway has definitively rejected.
    pub fn clear(&mut self) {
        *self.credential = None;
    }
}

/// Process-lifetime registry of sessions used by multi-provider clients.
#[derive(Clone, Default)]
pub struct SessionManager {
    slots: Arc<StdMutex<HashMap<SessionKey, SessionSlot>>>,
}

impl SessionManager {
    pub fn slot(
        &self,
        resource_url: &str,
        network: Option<&str>,
        account: Option<&str>,
    ) -> Result<SessionSlot> {
        let key = SessionKey::for_resource(resource_url, network, account)?;
        let mut slots = self
            .slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(slots.entry(key).or_default().clone())
    }
}

/// Authorization pair prepared for the first request and later reuse.
pub struct PreparedOperatorSession {
    pub open_authorization: String,
    pub use_authorization: String,
}

/// Whether this challenge can produce a reusable agent session credential.
pub fn is_operator_session(challenge: &PaymentChallenge) -> bool {
    challenge
        .request
        .decode::<SessionRequest>()
        .ok()
        .is_some_and(|request| {
            request.method_details.voucher_signer == Some(SessionVoucherSigner::Operator)
        })
}

/// Open an operator-signed MPP session and prepare its reusable `use` proof.
///
/// The caller must cache `use_authorization` only after the request carrying
/// `open_authorization` receives a non-402 response.
#[allow(clippy::too_many_arguments)]
pub fn prepare_operator_session_with_override(
    challenge: &PaymentChallenge,
    store: &dyn AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
    resource_url: &str,
    sandbox: bool,
    auth_override: crate::signer::AuthOverride,
) -> Result<PreparedOperatorSession> {
    let request: SessionRequest = challenge
        .request
        .decode()
        .map_err(|error| Error::Mpp(format!("invalid MPP session challenge: {error}")))?;
    if request.method_details.voucher_signer != Some(SessionVoucherSigner::Operator) {
        return Err(Error::Mpp(
            "reusable agent sessions require voucherSigner `operator`".to_string(),
        ));
    }
    if let Some(forced) = network_override
        && forced != request.method_details.network
    {
        return Err(Error::Mpp(format!(
            "MPP session network mismatch: client requires `{forced}`, gateway offered `{}`",
            request.method_details.network
        )));
    }

    let deposit = session_deposit(&request)?;
    let (handle, open_authorization) = session::open_payment_channel_session_header_with_override(
        challenge,
        &request,
        store,
        network_override,
        account_override,
        deposit,
        resource_url,
        sandbox,
        auth_override,
    )?;
    let use_authorization = session::use_header_sync(&handle)?;

    Ok(PreparedOperatorSession {
        open_authorization,
        use_authorization,
    })
}

fn session_deposit(request: &SessionRequest) -> Result<u64> {
    let minimum =
        parse_optional_amount("minimumDeposit", request.minimum_deposit.as_deref())?.unwrap_or(0);
    let suggested =
        parse_optional_amount("suggestedDeposit", request.suggested_deposit.as_deref())?
            .unwrap_or(1_000_000);
    Ok(suggested.max(minimum).max(1))
}

fn parse_optional_amount(field: &str, value: Option<&str>) -> Result<Option<u64>> {
    value
        .map(|value| {
            value.parse::<u64>().map_err(|_| {
                Error::Mpp(format!(
                    "MPP session challenge advertised a non-numeric {field}: `{value}`"
                ))
            })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_key_is_scoped_to_origin_and_payer_context() {
        let first = SessionKey::for_resource(
            "https://api.example.com/v1/chat?model=x",
            Some("mainnet"),
            Some("payer-a"),
        )
        .unwrap();
        let same_origin = SessionKey::for_resource(
            "https://api.example.com/v1/models",
            Some("mainnet"),
            Some("payer-a"),
        )
        .unwrap();
        let other_payer = SessionKey::for_resource(
            "https://api.example.com/v1/chat",
            Some("mainnet"),
            Some("payer-b"),
        )
        .unwrap();

        assert_eq!(first, same_origin);
        assert_ne!(first, other_payer);
    }

    #[test]
    fn manager_reuses_a_slot_for_the_same_scope() {
        let manager = SessionManager::default();
        let first = manager
            .slot("https://api.example.com/a", None, None)
            .unwrap();
        let second = manager
            .slot("https://api.example.com/b", None, None)
            .unwrap();

        first
            .blocking_acquire()
            .adopt("Payment use-proof".to_string());
        assert_eq!(
            second.blocking_acquire().authorization(),
            Some("Payment use-proof")
        );
    }

    #[test]
    fn manager_isolates_different_origins() {
        let manager = SessionManager::default();
        let first = manager
            .slot("https://one.example.com/a", None, None)
            .unwrap();
        let second = manager
            .slot("https://two.example.com/a", None, None)
            .unwrap();

        first
            .blocking_acquire()
            .adopt("Payment use-proof".to_string());
        assert!(second.blocking_acquire().authorization().is_none());
    }
}
