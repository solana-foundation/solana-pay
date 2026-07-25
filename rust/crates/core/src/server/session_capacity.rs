//! Exclusive capacity leases for delegated MPP sessions.
//!
//! Local: process-private `HashSet`. Redis: an expiring lease plus a slightly
//! longer takeover barrier, both carrying the acquisition token.
//!
//! A Redis lease is renewed by a task owned by the returned
//! [`CapacityLeaseToken`], so a lease stays exclusive for as long as the holder
//! keeps the token — including streams that run far longer than the TTL. The
//! TTL is the crash bound: when a replica dies the key expires within it.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::{Error, Result};

/// How long a Redis lease survives without renewal (crash bound).
pub const CAPACITY_LEASE_TTL: Duration = Duration::from_secs(60);

/// Upper bound on any single lease command, connect included.
#[cfg(feature = "redis-session-store")]
const LEASE_IO_TIMEOUT: Duration = Duration::from_secs(2);

/// Renew at a third of the TTL so a lease survives two failed renewals.
#[cfg(feature = "redis-session-store")]
fn renew_interval(ttl: Duration) -> Duration {
    (ttl / 3).max(Duration::from_millis(100))
}

/// Keep a replacement holder out until the old holder's expiry watchdog has
/// fired. This closes the takeover gap if the lease key alone is deleted,
/// evicted, or replaced between renewal probes.
#[cfg(feature = "redis-session-store")]
fn barrier_ttl(ttl: Duration) -> Duration {
    ttl + renew_interval(ttl)
}

/// Keep the holder's Redis key alive; aborts when the token is dropped.
#[cfg(feature = "redis-session-store")]
struct RenewalTask(tokio::task::JoinHandle<()>);

#[cfg(feature = "redis-session-store")]
impl Drop for RenewalTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Proof of one acquisition. Must be passed back to
/// [`CapacityLeaseCoordinator::release`]; dropping it stops Redis renewal.
///
/// Boxed so an in-flight request holds one pointer, not the whole hold.
pub struct CapacityLeaseToken {
    #[cfg(feature = "redis-session-store")]
    redis: Option<Box<RedisLeaseHold>>,
}

/// Identity of a Redis lease plus the task keeping it alive.
#[cfg(feature = "redis-session-store")]
struct RedisLeaseHold {
    id: String,
    state: Arc<tokio::sync::watch::Sender<LeaseState>>,
    _renewal: Option<RenewalTask>,
}

/// Local proof of the last Redis renewal. The deadline lets a paused replica
/// reject its stale token immediately on resume, even before its watchdog runs.
#[cfg(feature = "redis-session-store")]
#[derive(Clone, Copy)]
struct LeaseState {
    held: bool,
    expires_at: tokio::time::Instant,
}

impl CapacityLeaseToken {
    /// The local backend needs no identity: the `HashSet` entry is the lease.
    fn local() -> Self {
        Self {
            #[cfg(feature = "redis-session-store")]
            redis: None,
        }
    }

    /// False once renewal proves the lease was lost — the holder must stop the
    /// work it was protecting, because a peer may already own the channel.
    pub fn is_held(&self) -> bool {
        #[cfg(feature = "redis-session-store")]
        if let Some(hold) = &self.redis {
            let state = *hold.state.borrow();
            return state.held && tokio::time::Instant::now() < state.expires_at;
        }
        true
    }

    /// Run `work` under this lease, abandoning it if the lease is lost first.
    ///
    /// Cancelling beats finishing here: once a peer owns the channel, our
    /// voucher or settlement would race theirs. Dropping `work` part-way is
    /// safe because every step it performs is a store compare-and-set or an
    /// idempotent on-chain settle that the new owner can redo.
    pub async fn guard<T>(&self, work: impl std::future::Future<Output = T>) -> Result<T> {
        tokio::select! {
            biased;
            () = self.lost() => Err(Error::Mpp(
                "capacity lease was lost before the protected work finished".to_string(),
            )),
            done = work => Ok(done),
        }
    }

    /// Resolves when the lease is lost, so callers can cancel work that is
    /// already in flight instead of only checking before they start.
    pub async fn lost(&self) {
        #[cfg(feature = "redis-session-store")]
        if let Some(hold) = &self.redis {
            let mut state = hold.state.subscribe();
            loop {
                let current = *state.borrow();
                if !current.held || tokio::time::Instant::now() >= current.expires_at {
                    return;
                }
                tokio::select! {
                    biased;
                    () = tokio::time::sleep_until(current.expires_at) => return,
                    changed = state.changed() => {
                        // A closed channel means the holder itself is going away.
                        if changed.is_err() {
                            return;
                        }
                    }
                }
            }
        }
        // A local lease cannot be taken away while the holder keeps its token.
        std::future::pending().await
    }
}

/// Coordinates exclusive access to a session channel's remaining capacity.
#[derive(Clone)]
pub struct CapacityLeaseCoordinator {
    inner: Arc<Inner>,
}

enum Inner {
    Local(Mutex<HashSet<String>>),
    #[cfg(feature = "redis-session-store")]
    Redis(RedisLease),
}

#[cfg(feature = "redis-session-store")]
#[derive(Clone)]
struct RedisLease {
    connection: redis::aio::ConnectionManager,
    prefix: String,
    ttl: Duration,
}

impl CapacityLeaseCoordinator {
    pub fn local() -> Self {
        Self {
            inner: Arc::new(Inner::Local(Mutex::new(HashSet::new()))),
        }
    }

    /// Shared Redis leases. `prefix` should match `PAY_SESSION_REDIS_PREFIX`.
    #[cfg(feature = "redis-session-store")]
    pub async fn redis(redis_url: &str, prefix: impl Into<String>) -> Result<Self> {
        Self::redis_with_ttl(redis_url, prefix, CAPACITY_LEASE_TTL).await
    }

    #[cfg(feature = "redis-session-store")]
    pub(crate) async fn redis_with_ttl(
        redis_url: &str,
        prefix: impl Into<String>,
        ttl: Duration,
    ) -> Result<Self> {
        let client = redis::Client::open(redis_url).map_err(lease_error)?;
        // Every lease call is on a request path, so bound the wait ourselves:
        // redis-rs retries a rejected handshake for minutes on its own.
        let config = redis::aio::ConnectionManagerConfig::new()
            .set_number_of_retries(2)
            .set_connection_timeout(LEASE_IO_TIMEOUT)
            .set_response_timeout(LEASE_IO_TIMEOUT);
        let connection =
            with_lease_timeout("connect", client.get_connection_manager_with_config(config))
                .await?
                .map_err(lease_error)?;
        Ok(Self {
            inner: Arc::new(Inner::Redis(RedisLease {
                connection,
                prefix: normalize_prefix(prefix.into()),
                ttl,
            })),
        })
    }

    /// `Ok(None)` means another holder owns the channel; `Err` means the lease
    /// backend is unreachable, which callers must not report as contention.
    pub async fn try_acquire(&self, channel_id: &str) -> Result<Option<CapacityLeaseToken>> {
        match self.inner.as_ref() {
            Inner::Local(slots) => {
                let mut slots = slots.lock().map_err(|_| lease_poisoned())?;
                Ok(slots
                    .insert(channel_id.to_string())
                    .then(CapacityLeaseToken::local))
            }
            #[cfg(feature = "redis-session-store")]
            Inner::Redis(lease) => lease.try_acquire(channel_id).await,
        }
    }

    pub fn release(&self, channel_id: &str, token: &CapacityLeaseToken) {
        let _ = token;
        match self.inner.as_ref() {
            Inner::Local(slots) => {
                if let Ok(mut slots) = slots.lock() {
                    slots.remove(channel_id);
                }
            }
            #[cfg(feature = "redis-session-store")]
            Inner::Redis(lease) => {
                if let Some(hold) = &token.redis {
                    lease.release_spawn(channel_id, &hold.id);
                }
            }
        }
    }

    pub async fn release_async(&self, channel_id: &str, token: &CapacityLeaseToken) {
        let _ = token;
        match self.inner.as_ref() {
            Inner::Local(slots) => {
                if let Ok(mut slots) = slots.lock() {
                    slots.remove(channel_id);
                }
            }
            #[cfg(feature = "redis-session-store")]
            Inner::Redis(lease) => {
                if let Some(hold) = &token.redis {
                    lease.release_now(channel_id, &hold.id).await;
                }
            }
        }
    }
}

/// Bound a lease call so a stalled backend surfaces as an error, not a hang.
#[cfg(feature = "redis-session-store")]
async fn with_lease_timeout<T>(
    what: &str,
    operation: impl std::future::Future<Output = T>,
) -> Result<T> {
    tokio::time::timeout(LEASE_IO_TIMEOUT, operation)
        .await
        .map_err(|_| Error::Mpp(format!("capacity lease backend timed out during {what}")))
}

fn lease_poisoned() -> Error {
    Error::Mpp("capacity lease registry lock poisoned".to_string())
}

#[cfg(feature = "redis-session-store")]
fn lease_error(error: impl std::fmt::Display) -> Error {
    Error::Mpp(format!("capacity lease backend unavailable: {error}"))
}

/// Acquire both keys atomically. A surviving barrier prevents takeover when
/// the lease key alone disappears before its holder observes the loss.
#[cfg(feature = "redis-session-store")]
const ACQUIRE_SCRIPT: &str = r"
if redis.call('EXISTS', KEYS[1]) == 1 or redis.call('EXISTS', KEYS[2]) == 1 then
  return 0
end
redis.call('PSETEX', KEYS[1], ARGV[2], ARGV[1])
redis.call('PSETEX', KEYS[2], ARGV[3], ARGV[1])
return 1
";

/// Renew only while both keys still prove ownership.
#[cfg(feature = "redis-session-store")]
const RENEW_SCRIPT: &str = r"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
if redis.call('GET', KEYS[2]) ~= ARGV[1] then return 0 end
redis.call('PEXPIRE', KEYS[1], ARGV[2])
redis.call('PEXPIRE', KEYS[2], ARGV[3])
return 1
";

#[cfg(feature = "redis-session-store")]
const RELEASE_SCRIPT: &str = r"
local deleted = 0
if redis.call('GET', KEYS[1]) == ARGV[1] then
  deleted = deleted + redis.call('DEL', KEYS[1])
end
if redis.call('GET', KEYS[2]) == ARGV[1] then
  deleted = deleted + redis.call('DEL', KEYS[2])
end
return deleted
";

#[cfg(feature = "redis-session-store")]
impl RedisLease {
    fn key(&self, channel_id: &str) -> String {
        format!("{}lease:{}", self.prefix, channel_id)
    }

    fn barrier_key(&self, channel_id: &str) -> String {
        format!("{}lease-barrier:{}", self.prefix, channel_id)
    }

    async fn try_acquire(&self, channel_id: &str) -> Result<Option<CapacityLeaseToken>> {
        let id = uuid::Uuid::new_v4().to_string();
        let key = self.key(channel_id);
        let barrier_key = self.barrier_key(channel_id);
        let mut conn = self.connection.clone();
        // Redis starts the clock when it runs the command, so date the deadline
        // from before we send: erring early keeps us inside the real TTL.
        let sent_at = tokio::time::Instant::now();
        let acquired: i32 = with_lease_timeout(
            "acquire",
            redis::Script::new(ACQUIRE_SCRIPT)
                .key(&key)
                .key(&barrier_key)
                .arg(&id)
                .arg(self.ttl.as_millis() as u64)
                .arg(barrier_ttl(self.ttl).as_millis() as u64)
                .invoke_async(&mut conn),
        )
        .await?
        .map_err(lease_error)?;
        if acquired == 0 {
            return Ok(None);
        }
        let expires_at = sent_at + self.ttl;
        let state = Arc::new(tokio::sync::watch::Sender::new(LeaseState {
            held: true,
            expires_at,
        }));
        let renewal = self
            .spawn_renewal(key, barrier_key, id.clone(), Arc::clone(&state), expires_at)
            .map(RenewalTask);
        Ok(Some(CapacityLeaseToken {
            redis: Some(Box::new(RedisLeaseHold {
                id,
                state,
                _renewal: renewal,
            })),
        }))
    }

    /// Extend the TTL for as long as the holder keeps its token, and declare the
    /// lease lost the moment we can no longer prove we still own the key.
    ///
    /// `expires_at` tracks when Redis will drop the key; every wait races it, so
    /// an unreachable Redis invalidates the lease instead of silently outliving
    /// it. Renewal is bounded by [`LEASE_IO_TIMEOUT`], so a stalled call cannot
    /// carry us past the deadline either.
    fn spawn_renewal(
        &self,
        key: String,
        barrier_key: String,
        id: String,
        state: Arc<tokio::sync::watch::Sender<LeaseState>>,
        mut expires_at: tokio::time::Instant,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let handle = tokio::runtime::Handle::try_current().ok()?;
        let mut conn = self.connection.clone();
        let ttl = self.ttl;
        Some(handle.spawn(async move {
            loop {
                let renewed = tokio::select! {
                    biased;
                    () = tokio::time::sleep_until(expires_at) => None,
                    () = tokio::time::sleep(renew_interval(ttl)) => {
                        let sent_at = tokio::time::Instant::now();
                        let call = with_lease_timeout("renew", async {
                            redis::Script::new(RENEW_SCRIPT)
                                .key(&key)
                                .key(&barrier_key)
                                .arg(&id)
                                .arg(ttl.as_millis() as u64)
                                .arg(barrier_ttl(ttl).as_millis() as u64)
                                .invoke_async::<i32>(&mut conn)
                                .await
                        });
                        tokio::select! {
                            biased;
                            () = tokio::time::sleep_until(expires_at) => None,
                            outcome = call => Some((sent_at, outcome)),
                        }
                    }
                };

                let Some((sent_at, outcome)) = renewed else {
                    tracing::warn!(key, "capacity lease expired before it could be renewed");
                    state.send_replace(LeaseState {
                        held: false,
                        expires_at,
                    });
                    return;
                };
                match outcome {
                    Ok(Ok(0)) => {
                        tracing::warn!(key, "capacity lease lost; another holder may own it");
                        state.send_replace(LeaseState {
                            held: false,
                            expires_at,
                        });
                        return;
                    }
                    Ok(Ok(_)) => {
                        expires_at = sent_at + ttl;
                        state.send_replace(LeaseState {
                            held: true,
                            expires_at,
                        });
                    }
                    // Keep trying until the deadline arm above fires.
                    Ok(Err(error)) => {
                        tracing::warn!(key, error = %error, "capacity lease renewal failed");
                    }
                    Err(error) => {
                        tracing::warn!(key, error = %error, "capacity lease renewal timed out");
                    }
                }
            }
        }))
    }

    async fn release_now(&self, channel_id: &str, id: &str) {
        let key = self.key(channel_id);
        let barrier_key = self.barrier_key(channel_id);
        let mut conn = self.connection.clone();
        // The TTL cleans up after a failed release, so never block on one.
        let _ = with_lease_timeout("release", async {
            redis::Script::new(RELEASE_SCRIPT)
                .key(&key)
                .key(&barrier_key)
                .arg(id)
                .invoke_async::<i32>(&mut conn)
                .await
        })
        .await;
    }

    fn release_spawn(&self, channel_id: &str, id: &str) {
        let key = self.key(channel_id);
        let barrier_key = self.barrier_key(channel_id);
        let id = id.to_string();
        let mut conn = self.connection.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = with_lease_timeout("release", async {
                    redis::Script::new(RELEASE_SCRIPT)
                        .key(&key)
                        .key(&barrier_key)
                        .arg(&id)
                        .invoke_async::<i32>(&mut conn)
                        .await
                })
                .await;
            });
        }
    }
}

#[cfg(feature = "redis-session-store")]
fn normalize_prefix(prefix: String) -> String {
    if prefix.is_empty() || prefix.ends_with(':') {
        prefix
    } else {
        format!("{prefix}:")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn guard_runs_work_while_the_lease_is_held() {
        let c = CapacityLeaseCoordinator::local();
        let token = c.try_acquire("ch").await.unwrap().expect("lease");
        assert_eq!(token.guard(async { 7 }).await.unwrap(), 7);
    }

    #[tokio::test]
    async fn local_lease_is_exclusive_until_released() {
        let c = CapacityLeaseCoordinator::local();
        let a = c.try_acquire("ch-a").await.unwrap().expect("a");
        assert!(c.try_acquire("ch-a").await.unwrap().is_none());
        assert!(c.try_acquire("ch-b").await.unwrap().is_some());
        c.release_async("ch-a", &a).await;
        assert!(c.try_acquire("ch-a").await.unwrap().is_some());
    }
}

#[cfg(all(test, feature = "redis-session-store"))]
pub(crate) mod redis_test_support {
    //! Shared Redis lease-test helpers for pay-core.
    //!
    //! Soft-skip when no URL is set locally. Under CI (`CI=true`) or
    //! `PAY_REQUIRE_REDIS_TESTS=1`, a missing URL panics so coverage cannot go
    //! vacuous.
    //!
    //! Product ceilings intentionally out of scope for the harness:
    //! - no fencing token beyond the lease id / barrier pair
    //! - `last_activity` is per-process (no shared idle clock across replicas)
    //! - lifecycle is "whoever holds the lease", not a leader election

    use super::*;
    use std::time::Duration;

    pub(crate) fn require_redis_tests() -> bool {
        matches!(std::env::var("PAY_REQUIRE_REDIS_TESTS").as_deref(), Ok("1") | Ok("true"))
            || matches!(std::env::var("CI").as_deref(), Ok("true") | Ok("1"))
    }

    fn redis_url_optional() -> Option<String> {
        std::env::var("PAY_SESSION_REDIS_URL")
            .or_else(|_| std::env::var("PAY_KIT_TEST_REDIS_URL"))
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    /// Soft-skip locally; panic in CI / when Redis tests are required.
    pub(crate) fn redis_test_url() -> Option<String> {
        match redis_url_optional() {
            Some(url) => Some(url),
            None if require_redis_tests() => {
                panic!(
                    "PAY_SESSION_REDIS_URL or PAY_KIT_TEST_REDIS_URL is required when \
                     CI=true or PAY_REQUIRE_REDIS_TESTS=1"
                );
            }
            None => None,
        }
    }

    pub(crate) fn unique_prefix(kind: &str) -> String {
        format!("pay:test:{kind}:{}:", uuid::Uuid::new_v4().simple())
    }

    pub(crate) async fn dual_coordinators(
        ttl: Duration,
    ) -> Option<(String, String, CapacityLeaseCoordinator, CapacityLeaseCoordinator)> {
        let url = redis_test_url()?;
        let prefix = unique_prefix("lease");
        let a = CapacityLeaseCoordinator::redis_with_ttl(&url, &prefix, ttl)
            .await
            .expect("coordinator a");
        let b = CapacityLeaseCoordinator::redis_with_ttl(&url, &prefix, ttl)
            .await
            .expect("coordinator b");
        Some((url, prefix, a, b))
    }

    pub(crate) async fn del_lease_key(url: &str, prefix: &str, channel_id: &str) {
        let client = redis::Client::open(url).expect("redis client");
        let mut conn = client.get_connection_manager().await.expect("redis conn");
        let _: () = redis::cmd("DEL")
            .arg(format!("{prefix}lease:{channel_id}"))
            .query_async(&mut conn)
            .await
            .expect("DEL lease key");
    }

    /// Peer must not acquire while the takeover barrier still proves the old hold.
    /// Never assert success as "peer acquires while the original is still held".
    pub(crate) async fn assert_no_overlapping_holders(
        peer: &CapacityLeaseCoordinator,
        channel_id: &str,
    ) {
        assert!(
            peer.try_acquire(channel_id).await.expect("peer acquire").is_none(),
            "the takeover barrier must prevent overlapping holders"
        );
    }
}

#[cfg(all(test, feature = "redis-session-store"))]
mod redis_tests {
    use super::*;
    use super::redis_test_support::{
        assert_no_overlapping_holders, del_lease_key, dual_coordinators, redis_test_url,
        unique_prefix,
    };

    #[tokio::test]
    async fn redis_lease_exclusive_and_stale_release_safe() {
        let Some((url, prefix, a, b)) = dual_coordinators(Duration::from_millis(600)).await else {
            eprintln!("skipping: set PAY_SESSION_REDIS_URL or PAY_KIT_TEST_REDIS_URL");
            return;
        };

        let mut token_a = a.try_acquire("ch").await.unwrap().expect("a");
        assert!(b.try_acquire("ch").await.unwrap().is_none());

        // Stop A's watchdog and wait for both of its keys to expire naturally.
        // Its local deadline is stale before B is allowed to acquire.
        token_a.redis.as_mut().expect("redis hold")._renewal.take();
        tokio::time::sleep(barrier_ttl(Duration::from_millis(600)) + Duration::from_millis(100))
            .await;
        assert!(!token_a.is_held());

        let token_b = b.try_acquire("ch").await.unwrap().expect("b");
        let key = format!("{prefix}lease:ch");
        let client = redis::Client::open(url.as_str()).unwrap();
        let mut conn = client.get_connection_manager().await.unwrap();

        // A's late release must not delete B's token.
        a.release_async("ch", &token_a).await;
        let value: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(
            value.is_some(),
            "stale compare-and-delete must leave new holder"
        );
        b.release_async("ch", &token_b).await;
    }

    #[tokio::test]
    async fn redis_lease_renews_past_its_ttl() {
        let Some(url) = redis_test_url() else {
            eprintln!("skipping: set PAY_SESSION_REDIS_URL or PAY_KIT_TEST_REDIS_URL");
            return;
        };
        let prefix = unique_prefix("lease");
        let ttl = Duration::from_millis(600);
        let coordinator = CapacityLeaseCoordinator::redis_with_ttl(&url, &prefix, ttl)
            .await
            .unwrap();
        let token = coordinator.try_acquire("ch").await.unwrap().expect("lease");

        // Outlive the TTL: only renewal can keep the key (and the exclusion) alive.
        tokio::time::sleep(ttl * 3).await;

        let peer = CapacityLeaseCoordinator::redis_with_ttl(&url, &prefix, ttl)
            .await
            .unwrap();
        assert!(
            peer.try_acquire("ch").await.unwrap().is_none(),
            "renewed lease must stay exclusive past its TTL"
        );

        // Dropping the token stops renewal, so the lease lapses on its own.
        drop(token);
        tokio::time::sleep(ttl * 2).await;
        assert!(peer.try_acquire("ch").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn redis_backend_failure_is_an_error_not_contention() {
        let Some(url) = redis_test_url() else {
            eprintln!("skipping: set PAY_SESSION_REDIS_URL or PAY_KIT_TEST_REDIS_URL");
            return;
        };
        // A rejected handshake stands in for any backend failure: it must never
        // look like a channel that is merely busy.
        let rejected = url.replacen("redis://", "redis://:wrong-password@", 1);
        let acquired = match CapacityLeaseCoordinator::redis(&rejected, "pay:test:broken:").await {
            Ok(coordinator) => coordinator.try_acquire("ch").await,
            Err(error) => Err(error),
        };
        assert!(
            acquired.is_err(),
            "backend failure must surface as an error"
        );
    }

    #[tokio::test]
    async fn lost_redis_lease_marks_the_token_unheld() {
        let Some((url, prefix, coordinator, peer)) =
            dual_coordinators(Duration::from_millis(600)).await
        else {
            eprintln!("skipping: set PAY_SESSION_REDIS_URL or PAY_KIT_TEST_REDIS_URL");
            return;
        };
        let ttl = Duration::from_millis(600);
        let token = coordinator.try_acquire("ch").await.unwrap().expect("lease");
        assert!(token.is_held());

        // Delete only the lease key behind the holder's back. The barrier must
        // keep a peer out until the original holder observes the loss.
        del_lease_key(&url, &prefix, "ch").await;
        assert_no_overlapping_holders(&peer, "ch").await;

        tokio::time::timeout(ttl * 4, token.lost())
            .await
            .expect("losing the lease must wake work waiting on it");
        assert!(
            !token.is_held(),
            "renewal must tell the holder its lease is gone"
        );
        coordinator.release_async("ch", &token).await;
        let peer_token = peer.try_acquire("ch").await.unwrap().expect("peer");
        assert!(peer_token.is_held());
    }

    #[tokio::test]
    async fn loss_is_persisted_without_an_active_waiter() {
        let Some((url, prefix, coordinator, _)) =
            dual_coordinators(Duration::from_millis(600)).await
        else {
            eprintln!("skipping: set PAY_SESSION_REDIS_URL or PAY_KIT_TEST_REDIS_URL");
            return;
        };
        let ttl = Duration::from_millis(600);
        let token = coordinator.try_acquire("ch").await.unwrap().expect("lease");

        del_lease_key(&url, &prefix, "ch").await;

        // No receiver is active while the watchdog detects the loss.
        tokio::time::sleep(renew_interval(ttl) * 2).await;
        assert!(!token.is_held(), "loss must persist in the watch value");
        assert!(
            token.guard(async { 7 }).await.is_err(),
            "work started after detection must fail immediately"
        );
    }

    #[tokio::test]
    async fn expired_local_deadline_rejects_a_stale_token() {
        let token = CapacityLeaseToken {
            redis: Some(Box::new(RedisLeaseHold {
                id: "stale".to_string(),
                state: Arc::new(tokio::sync::watch::Sender::new(LeaseState {
                    held: true,
                    expires_at: tokio::time::Instant::now(),
                })),
                _renewal: None,
            })),
        };

        assert!(!token.is_held());
        assert!(
            token.guard(async { 7 }).await.is_err(),
            "a paused replica must reject an expired token on resume"
        );
    }

    #[tokio::test]
    async fn early_deletion_after_renewal_cannot_overlap_holders() {
        let Some((url, prefix, owner, peer)) =
            dual_coordinators(Duration::from_millis(600)).await
        else {
            eprintln!("skipping: set PAY_SESSION_REDIS_URL or PAY_KIT_TEST_REDIS_URL");
            return;
        };
        let ttl = Duration::from_millis(600);
        let token = owner.try_acquire("ch").await.unwrap().expect("owner");

        // Wait for proof that one renewal completed, then delete only the lease
        // key just after it. Sleeping for one interval is not synchronization.
        let initial_expiry = token
            .redis
            .as_ref()
            .expect("redis hold")
            .state
            .borrow()
            .expires_at;
        let mut state = token.redis.as_ref().expect("redis hold").state.subscribe();
        tokio::time::timeout(ttl, async {
            loop {
                if state.borrow().expires_at > initial_expiry {
                    break;
                }
                state.changed().await.unwrap();
            }
        })
        .await
        .expect("renewal must complete");

        del_lease_key(&url, &prefix, "ch").await;

        assert_no_overlapping_holders(&peer, "ch").await;
        tokio::time::timeout(ttl, token.lost())
            .await
            .expect("owner must detect the loss before the barrier expires");
        owner.release_async("ch", &token).await;
        assert!(peer.try_acquire("ch").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn guard_abandons_in_flight_work_when_the_lease_is_lost() {
        let Some((url, prefix, coordinator, peer)) =
            dual_coordinators(Duration::from_millis(600)).await
        else {
            eprintln!("skipping: set PAY_SESSION_REDIS_URL or PAY_KIT_TEST_REDIS_URL");
            return;
        };
        let ttl = Duration::from_millis(600);
        let token = coordinator.try_acquire("ch").await.unwrap().expect("lease");

        // Delete only the lease key while guarded work is still running. A peer
        // remains blocked by the barrier until the holder cancels its work.
        del_lease_key(&url, &prefix, "ch").await;
        assert_no_overlapping_holders(&peer, "ch").await;

        let work_finished = Arc::new(Mutex::new(false));
        let flag = Arc::clone(&work_finished);
        let guarded = token.guard(async move {
            tokio::time::sleep(ttl * 10).await;
            *flag.lock().unwrap() = true;
        });

        let error = tokio::time::timeout(ttl * 4, guarded)
            .await
            .expect("guard must return once the lease is lost")
            .expect_err("a lost lease must abandon the work");
        assert!(error.to_string().contains("capacity lease was lost"));
        assert!(
            !*work_finished.lock().unwrap(),
            "guarded work must not run to completion after the lease is lost"
        );
        coordinator.release_async("ch", &token).await;
        assert!(
            peer.try_acquire("ch").await.unwrap().is_some(),
            "a peer may acquire only after the old holder has cancelled"
        );
    }

    #[tokio::test]
    async fn acquire_stampede_yields_exactly_one_holder() {
        let Some(url) = redis_test_url() else {
            eprintln!("skipping: set PAY_SESSION_REDIS_URL or PAY_KIT_TEST_REDIS_URL");
            return;
        };
        let prefix = unique_prefix("stampede");
        let ttl = Duration::from_millis(600);
        let mut coordinators = Vec::new();
        for _ in 0..8 {
            coordinators.push(
                CapacityLeaseCoordinator::redis_with_ttl(&url, &prefix, ttl)
                    .await
                    .unwrap(),
            );
        }
        let mut tasks = Vec::new();
        for coordinator in &coordinators {
            let c = coordinator.clone();
            tasks.push(async move { c.try_acquire("ch").await.unwrap() });
        }
        let results = futures_util::future::join_all(tasks).await;
        let winners: Vec<_> = results.into_iter().flatten().collect();
        assert_eq!(
            winners.len(),
            1,
            "exactly one stampede participant may hold the lease"
        );
    }
}
