//! Linux: Polkit authentication + GNOME Secret Service storage.

use crate::{AuthGate, AuthIntent, Error, Result, SecretStore, Zeroizing};
use secret_service::{EncryptionType, SecretService};
use std::collections::HashMap;

// ── Polkit auth gate ────────────────────────────────────────────────────────

const POLKIT_ACTION_PAYMENT: &str = "sh.pay.authorize-payment";
const POLKIT_ACTION_CREATE: &str = "sh.pay.create-keypair";
const POLKIT_ACTION_IMPORT: &str = "sh.pay.import-keypair";
const POLKIT_ACTION_EXPORT: &str = "sh.pay.export-keypair";
const POLKIT_ACTION_DELETE: &str = "sh.pay.delete-keypair";
const POLKIT_ACTION_SESSION: &str = "sh.pay.open-session";
const POLKIT_ACTION_GATEWAY_FEE_PAYER: &str = "sh.pay.use-gateway-fee-payer";
const POLKIT_ACTION_USE: &str = "sh.pay.use-keypair";
const LEGACY_POLKIT_ACTION: &str = "sh.pay.unlock-keypair";

pub struct Polkit;

impl AuthGate for Polkit {
    fn authenticate(&self, intent: &AuthIntent) -> Result<()> {
        let action = polkit_action_for_intent(intent);
        run(async move {
            match polkit_authenticate(action).await {
                Err(e) if action != LEGACY_POLKIT_ACTION && is_missing_action(&e) => {
                    polkit_authenticate(LEGACY_POLKIT_ACTION).await
                }
                result => result,
            }
        })
    }

    fn is_available(&self) -> bool {
        local_auth_prompt_environment(
            std::env::var_os("DISPLAY").as_deref(),
            std::env::var_os("WAYLAND_DISPLAY").as_deref(),
        ) && run(async { zbus::Connection::system().await.is_ok() })
    }
}

/// Whether this process is attached to a graphical session where a Polkit
/// authentication agent can display a prompt.
///
/// Secret Service and Polkit can both be reachable over D-Bus in an SSH or
/// systemd service session without any agent capable of answering a challenge.
/// Treating that as local-auth availability suppresses MCP elicitation and
/// leaves the request waiting on a prompt that cannot be shown.
fn local_auth_prompt_environment(
    display: Option<&std::ffi::OsStr>,
    wayland_display: Option<&std::ffi::OsStr>,
) -> bool {
    display.is_some_and(|value| !value.is_empty())
        || wayland_display.is_some_and(|value| !value.is_empty())
}

async fn polkit_authenticate(action: &str) -> Result<()> {
    use zbus::zvariant::{OwnedValue, Value};

    let conn = zbus::Connection::system()
        .await
        .map_err(|e| Error::Backend(format!("D-Bus system bus: {e}")))?;

    let pid = std::process::id();
    let start_time = process_start_time()?;

    let subject_details: HashMap<String, OwnedValue> = [
        ("pid".to_owned(), OwnedValue::from(Value::new(pid))),
        (
            "start-time".to_owned(),
            OwnedValue::from(Value::new(start_time)),
        ),
    ]
    .into();

    let details: HashMap<String, String> = HashMap::new();
    let flags: u32 = 0x1; // AllowUserInteraction

    let reply = conn
        .call_method(
            Some("org.freedesktop.PolicyKit1"),
            "/org/freedesktop/PolicyKit1/Authority",
            Some("org.freedesktop.PolicyKit1.Authority"),
            "CheckAuthorization",
            &(
                ("unix-process", subject_details),
                action,
                details,
                flags,
                "",
            ),
        )
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("No such action") || msg.contains("not registered") {
                missing_action_error(action)
            } else {
                Error::Backend(format!("polkit: {msg}"))
            }
        })?;

    let (authorized, _, _): (bool, bool, HashMap<String, String>) = reply
        .body()
        .map_err(|e| Error::Backend(format!("polkit response: {e}")))?;

    if authorized {
        Ok(())
    } else {
        Err(Error::AuthDenied("authentication cancelled".to_string()))
    }
}

fn polkit_action_for_intent(intent: &AuthIntent) -> &'static str {
    match intent {
        AuthIntent::AuthorizePayment { limit, .. } => limit
            .map(polkit_payment_limit_action)
            .unwrap_or(POLKIT_ACTION_PAYMENT),
        AuthIntent::CreateAccount(_) => POLKIT_ACTION_CREATE,
        AuthIntent::ImportAccount(_) => POLKIT_ACTION_IMPORT,
        AuthIntent::ExportAccount(_) => POLKIT_ACTION_EXPORT,
        AuthIntent::DeleteAccount(_) => POLKIT_ACTION_DELETE,
        AuthIntent::OpenSession(_) => POLKIT_ACTION_SESSION,
        AuthIntent::UseGatewayFeePayer(_) => POLKIT_ACTION_GATEWAY_FEE_PAYER,
        AuthIntent::UseAccount(_) => POLKIT_ACTION_USE,
    }
}

fn polkit_payment_limit_action(limit: crate::PaymentLimit) -> &'static str {
    match limit {
        crate::PaymentLimit::Usd00001 => "sh.pay.authorize-payment-up-to-usd-00001",
        crate::PaymentLimit::Usd0001 => "sh.pay.authorize-payment-up-to-usd-0001",
        crate::PaymentLimit::Usd0005 => "sh.pay.authorize-payment-up-to-usd-0005",
        crate::PaymentLimit::Usd001 => "sh.pay.authorize-payment-up-to-usd-001",
        crate::PaymentLimit::Usd005 => "sh.pay.authorize-payment-up-to-usd-005",
        crate::PaymentLimit::Usd01 => "sh.pay.authorize-payment-up-to-usd-01",
        crate::PaymentLimit::Usd05 => "sh.pay.authorize-payment-up-to-usd-05",
        crate::PaymentLimit::Usd1 => "sh.pay.authorize-payment-up-to-usd-1",
        crate::PaymentLimit::Usd2 => "sh.pay.authorize-payment-up-to-usd-2",
        crate::PaymentLimit::Usd5 => "sh.pay.authorize-payment-up-to-usd-5",
        crate::PaymentLimit::Usd10 => "sh.pay.authorize-payment-up-to-usd-10",
        crate::PaymentLimit::Usd15 => "sh.pay.authorize-payment-up-to-usd-15",
        crate::PaymentLimit::Usd20 => "sh.pay.authorize-payment-up-to-usd-20",
        crate::PaymentLimit::Usd25 => "sh.pay.authorize-payment-up-to-usd-25",
        crate::PaymentLimit::Usd50 => "sh.pay.authorize-payment-up-to-usd-50",
        crate::PaymentLimit::AboveUsd50 => "sh.pay.authorize-payment-above-usd-50",
    }
}

fn missing_action_error(action: &str) -> Error {
    Error::Backend(format!(
        "polkit action '{action}' is not installed.\n\
         Run `pay setup` to install the embedded policy, or install it manually with:\n\
         \x20 sudo cp rust/config/polkit/sh.pay.unlock-keypair.policy \\\n\
         \x20      /usr/share/polkit-1/actions/"
    ))
}

fn is_missing_action(error: &Error) -> bool {
    matches!(error, Error::Backend(msg) if msg.contains("is not installed"))
}

fn process_start_time() -> Result<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat")
        .map_err(|e| Error::Backend(format!("read /proc/self/stat: {e}")))?;
    let after_comm = stat
        .rfind(')')
        .ok_or_else(|| Error::Backend("parse /proc/self/stat".to_string()))?;
    let fields: Vec<&str> = stat[after_comm + 2..].split_ascii_whitespace().collect();
    fields
        .get(19)
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| Error::Backend("parse /proc/self/stat: starttime field missing".to_string()))
}

// ── Secret Service store ────────────────────────────────────────────────────

const SERVICE_ATTR: &str = "pay.sh";
const COLLECTION_LABEL: &str = "pay";

pub struct SecretServiceStore;

impl SecretServiceStore {
    pub fn is_available() -> bool {
        run(async { SecretService::connect(EncryptionType::Dh).await.is_ok() })
    }
}

impl SecretStore for SecretServiceStore {
    fn store(&self, key: &str, data: &[u8]) -> Result<()> {
        let key = key.to_owned();
        let data = Zeroizing::new(data.to_owned());
        run(async move {
            let ss = connect().await?;
            let col = get_or_create_collection(&ss).await?;
            with_unlocked_collection(&col, || store_item(&col, &key, &data)).await
        })
    }

    fn load(&self, key: &str) -> Result<Zeroizing<Vec<u8>>> {
        let key = key.to_owned();
        run(async move {
            let ss = connect().await?;
            let col = get_collection(&ss).await.ok_or_else(|| {
                Error::Backend("pay keyring not found — run `pay setup` first".to_string())
            })?;
            with_unlocked_collection(&col, || async {
                let items = col.search_items(attrs(&key)).await.map_err(ss_err)?;
                let item = items
                    .first()
                    .ok_or_else(|| Error::Backend(format!("key not found: {key}")))?;
                Ok(Zeroizing::new(item.get_secret().await.map_err(ss_err)?))
            })
            .await
        })
    }

    fn exists(&self, key: &str) -> bool {
        let key = key.to_owned();
        run(async move {
            let Ok(ss) = connect().await else {
                return false;
            };
            let Some(col) = get_collection(&ss).await else {
                let Ok(default) = ss.get_default_collection().await else {
                    return false;
                };
                return default
                    .search_items(attrs(&key))
                    .await
                    .map(|items| !items.is_empty())
                    .unwrap_or(false);
            };
            col.search_items(attrs(&key))
                .await
                .map(|items| !items.is_empty())
                .unwrap_or(false)
        })
    }

    fn delete(&self, key: &str) -> Result<()> {
        let key = key.to_owned();
        run(async move {
            let ss = connect().await?;
            if let Some(col) = get_collection(&ss).await {
                with_unlocked_collection(&col, || async {
                    for item in col.search_items(attrs(&key)).await.map_err(ss_err)? {
                        item.delete().await.map_err(ss_err)?;
                    }
                    Ok(())
                })
                .await?;
            }
            if let Ok(default) = ss.get_default_collection().await {
                for item in default.search_items(attrs(&key)).await.map_err(ss_err)? {
                    item.delete().await.map_err(ss_err)?;
                }
            }
            Ok(())
        })
    }
}

// ── Secret Service helpers ──────────────────────────────────────────────────

async fn connect() -> Result<SecretService<'static>> {
    SecretService::connect(EncryptionType::Dh)
        .await
        .map_err(|e| Error::Backend(format!("Secret Service unavailable: {e}")))
}

async fn get_collection<'a>(ss: &'a SecretService<'a>) -> Option<secret_service::Collection<'a>> {
    let collections = ss.get_all_collections().await.ok()?;
    for col in collections {
        if col
            .get_label()
            .await
            .map(|l| l == COLLECTION_LABEL)
            .unwrap_or(false)
        {
            return Some(col);
        }
    }
    None
}

async fn get_or_create_collection<'a>(
    ss: &'a SecretService<'a>,
) -> Result<secret_service::Collection<'a>> {
    if let Some(col) = get_collection(ss).await {
        return Ok(col);
    }
    ss.create_collection(COLLECTION_LABEL, "")
        .await
        .map_err(ss_err)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CollectionLockState {
    Locked,
    Unlocked,
}

impl CollectionLockState {
    fn should_relock(self) -> bool {
        matches!(self, Self::Locked)
    }
}

trait CollectionLock {
    type Error: std::fmt::Display;

    async fn is_locked(&self) -> std::result::Result<bool, Self::Error>;
    async fn unlock(&self) -> std::result::Result<(), Self::Error>;
    async fn lock(&self) -> std::result::Result<(), Self::Error>;
}

impl CollectionLock for secret_service::Collection<'_> {
    type Error = secret_service::Error;

    async fn is_locked(&self) -> std::result::Result<bool, Self::Error> {
        secret_service::Collection::is_locked(self).await
    }

    async fn unlock(&self) -> std::result::Result<(), Self::Error> {
        secret_service::Collection::unlock(self).await
    }

    async fn lock(&self) -> std::result::Result<(), Self::Error> {
        secret_service::Collection::lock(self).await
    }
}

/// Run one operation with an unlocked collection, preserving the lock state
/// that the caller established before Pay touched it.
///
/// A headless service commonly keeps its keyring unlocked for its lifetime.
/// Locking that collection here would make the next operation require a Secret
/// Service prompt that cannot be displayed. Only relock when this call found
/// the collection locked and successfully unlocked it itself.
async fn with_unlocked_collection<C, F, Fut, T>(col: &C, operation: F) -> Result<T>
where
    C: CollectionLock + ?Sized,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let original_state = ensure_unlocked(col).await?;
    let result = operation().await;
    restore_lock_state(col, original_state).await;
    result
}

async fn ensure_unlocked<C>(col: &C) -> Result<CollectionLockState>
where
    C: CollectionLock + ?Sized,
{
    let original_state = if col.is_locked().await.unwrap_or(true) {
        CollectionLockState::Locked
    } else {
        CollectionLockState::Unlocked
    };

    if original_state == CollectionLockState::Locked {
        col.unlock().await.map_err(|e| {
            let msg = e.to_string().to_lowercase();
            if msg.contains("dismissed") || msg.contains("cancel") || msg.contains("denied") {
                Error::AuthDenied("keyring unlock cancelled".to_string())
            } else {
                Error::Backend(format!("unlock failed: {e}"))
            }
        })?;
    }
    Ok(original_state)
}

async fn restore_lock_state<C>(col: &C, original_state: CollectionLockState)
where
    C: CollectionLock + ?Sized,
{
    if original_state.should_relock() {
        // The operation may already have committed. A relock failure must not
        // turn that success into a reported failure and leave partial state.
        let _ = col.lock().await;
    }
}

async fn store_item(col: &secret_service::Collection<'_>, key: &str, secret: &[u8]) -> Result<()> {
    col.create_item(
        &format!("pay/{key}"),
        attrs(key),
        secret,
        true,
        "application/octet-stream",
    )
    .await
    .map_err(ss_err)
    .map(|_| ())
}

fn attrs(key: &str) -> HashMap<&str, &str> {
    HashMap::from([("service", SERVICE_ATTR), ("account", key)])
}

fn ss_err(e: secret_service::Error) -> Error {
    Error::Backend(e.to_string())
}

fn run<F, T>(future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[test]
    fn local_auth_prompt_requires_a_graphical_session() {
        use std::ffi::OsStr;

        assert!(!local_auth_prompt_environment(None, None));
        assert!(!local_auth_prompt_environment(
            Some(OsStr::new("")),
            Some(OsStr::new(""))
        ));
        assert!(local_auth_prompt_environment(Some(OsStr::new(":0")), None));
        assert!(local_auth_prompt_environment(
            None,
            Some(OsStr::new("wayland-0"))
        ));
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum LockEvent {
        IsLocked,
        Unlock,
        Operation,
        Lock,
    }

    struct FakeCollection {
        locked: Cell<bool>,
        fail_relock: bool,
        events: RefCell<Vec<LockEvent>>,
    }

    impl FakeCollection {
        fn new(locked: bool) -> Self {
            Self {
                locked: Cell::new(locked),
                fail_relock: false,
                events: RefCell::new(Vec::new()),
            }
        }

        fn with_failed_relock() -> Self {
            Self {
                fail_relock: true,
                ..Self::new(true)
            }
        }

        fn operation(&self) {
            self.events.borrow_mut().push(LockEvent::Operation);
        }
    }

    impl CollectionLock for FakeCollection {
        type Error = &'static str;

        async fn is_locked(&self) -> std::result::Result<bool, Self::Error> {
            self.events.borrow_mut().push(LockEvent::IsLocked);
            Ok(self.locked.get())
        }

        async fn unlock(&self) -> std::result::Result<(), Self::Error> {
            self.events.borrow_mut().push(LockEvent::Unlock);
            self.locked.set(false);
            Ok(())
        }

        async fn lock(&self) -> std::result::Result<(), Self::Error> {
            self.events.borrow_mut().push(LockEvent::Lock);
            if self.fail_relock {
                return Err("relock failed");
            }
            self.locked.set(true);
            Ok(())
        }
    }

    #[test]
    fn preunlocked_collection_stays_unlocked_across_import_writes() {
        let col = FakeCollection::new(false);

        run(async {
            for _ in 0..2 {
                with_unlocked_collection(&col, || async {
                    col.operation();
                    Ok(())
                })
                .await
                .unwrap();
            }
        });

        assert!(!col.locked.get());
        assert_eq!(
            *col.events.borrow(),
            [
                LockEvent::IsLocked,
                LockEvent::Operation,
                LockEvent::IsLocked,
                LockEvent::Operation,
            ]
        );
    }

    #[test]
    fn locked_collection_is_restored_after_operation() {
        let col = FakeCollection::new(true);

        run(with_unlocked_collection(&col, || async {
            col.operation();
            Ok(())
        }))
        .unwrap();

        assert!(col.locked.get());
        assert_eq!(
            *col.events.borrow(),
            [
                LockEvent::IsLocked,
                LockEvent::Unlock,
                LockEvent::Operation,
                LockEvent::Lock,
            ]
        );
    }

    #[test]
    fn operation_failure_still_restores_locked_collection() {
        let col = FakeCollection::new(true);

        let result: Result<()> = run(with_unlocked_collection(&col, || async {
            col.operation();
            Err(Error::Backend("operation failed".to_string()))
        }));

        assert!(matches!(result, Err(Error::Backend(message)) if message == "operation failed"));
        assert!(col.locked.get());
        assert_eq!(col.events.borrow().last(), Some(&LockEvent::Lock));
    }

    #[test]
    fn relock_failure_does_not_mask_completed_operation() {
        let col = FakeCollection::with_failed_relock();

        let value = run(with_unlocked_collection(&col, || async {
            col.operation();
            Ok(42)
        }))
        .unwrap();

        assert_eq!(value, 42);
        assert!(!col.locked.get());
        assert_eq!(col.events.borrow().last(), Some(&LockEvent::Lock));
    }

    #[test]
    fn payment_intents_use_payment_action() {
        assert_eq!(
            polkit_action_for_intent(&AuthIntent::authorize_payment(
                "$0.05",
                "accessing API api.example.com"
            )),
            "sh.pay.authorize-payment-up-to-usd-005"
        );
        assert_eq!(
            polkit_action_for_intent(&AuthIntent::default_payment()),
            POLKIT_ACTION_PAYMENT
        );
        assert_eq!(
            polkit_action_for_intent(&AuthIntent::send_sol("11111111111111111111111111111111")),
            POLKIT_ACTION_PAYMENT
        );
        assert_eq!(
            polkit_action_for_intent(&AuthIntent::authorize_payment("$0.0501", "accessing API")),
            "sh.pay.authorize-payment-up-to-usd-01"
        );
        assert_eq!(
            polkit_action_for_intent(&AuthIntent::authorize_payment("$50.01", "accessing API")),
            "sh.pay.authorize-payment-above-usd-50"
        );
    }

    #[test]
    fn account_lifecycle_intents_use_specific_actions() {
        assert_eq!(
            polkit_action_for_intent(&AuthIntent::create_account("default")),
            POLKIT_ACTION_CREATE
        );
        assert_eq!(
            polkit_action_for_intent(&AuthIntent::import_account("default")),
            POLKIT_ACTION_IMPORT
        );
        assert_eq!(
            polkit_action_for_intent(&AuthIntent::export_account("default")),
            POLKIT_ACTION_EXPORT
        );
        assert_eq!(
            polkit_action_for_intent(&AuthIntent::delete_account("default")),
            POLKIT_ACTION_DELETE
        );
        assert_eq!(
            polkit_action_for_intent(&AuthIntent::open_session()),
            POLKIT_ACTION_SESSION
        );
        assert_eq!(
            polkit_action_for_intent(&AuthIntent::use_gateway_fee_payer()),
            POLKIT_ACTION_GATEWAY_FEE_PAYER
        );
    }

    #[test]
    fn use_account_intent_uses_generic_action() {
        assert_eq!(
            polkit_action_for_intent(&AuthIntent::use_account(
                "Use your pay account with the Solana CLI."
            )),
            POLKIT_ACTION_USE
        );
    }
}
