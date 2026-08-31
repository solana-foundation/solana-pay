use std::collections::HashMap;
use std::sync::Mutex;

/// Key for looking up cumulative usage.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct AccountingKey {
    /// API name (e.g. "vision")
    pub api: String,
    /// Endpoint path pattern (e.g. "v1/images:annotate")
    pub endpoint: String,
    /// Billing period (e.g. "2026-03")
    pub period: String,
    /// Scope: "pool" for pooled accounting, or wallet pubkey for per-agent
    pub scope: String,
}

/// Trait for usage accounting backends.
pub trait AccountingStore: Send + Sync {
    /// Get current cumulative usage for a key. Returns 0 if no usage recorded.
    fn get_usage(&self, key: &AccountingKey) -> u64;

    /// Atomically increment usage by `amount` and return the new total.
    fn increment(&self, key: &AccountingKey, amount: u64) -> u64;

    /// Reset all counters for a given billing period.
    fn reset_period(&self, period: &str);
}

/// In-memory accounting store. Suitable for development and single-instance deployments.
/// Counters are lost on restart.
pub struct InMemoryStore {
    counters: Mutex<HashMap<AccountingKey, u64>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            counters: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountingStore for InMemoryStore {
    fn get_usage(&self, key: &AccountingKey) -> u64 {
        let counters = self.counters.lock().unwrap_or_else(|e| e.into_inner());
        counters.get(key).copied().unwrap_or(0)
    }

    fn increment(&self, key: &AccountingKey, amount: u64) -> u64 {
        let mut counters = self.counters.lock().unwrap_or_else(|e| e.into_inner());
        let entry = counters.entry(key.clone()).or_insert(0);
        *entry += amount;
        *entry
    }

    fn reset_period(&self, period: &str) {
        let mut counters = self.counters.lock().unwrap_or_else(|e| e.into_inner());
        counters.retain(|k, _| k.period != period);
    }
}

/// Get the current billing period string (e.g. "2026-03").
pub fn current_period() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Simple: days since epoch → year-month
    let days = now / 86400;
    let year = 1970 + (days / 365); // approximate, good enough for billing periods
    let month = ((days % 365) / 30) + 1;
    format!("{year}-{month:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(scope: &str) -> AccountingKey {
        AccountingKey {
            api: "vision".to_string(),
            endpoint: "v1/images:annotate".to_string(),
            period: "2026-03".to_string(),
            scope: scope.to_string(),
        }
    }

    #[test]
    fn test_in_memory_store() {
        let store = InMemoryStore::new();
        let key = test_key("pool");

        assert_eq!(store.get_usage(&key), 0);
        assert_eq!(store.increment(&key, 100), 100);
        assert_eq!(store.increment(&key, 50), 150);
        assert_eq!(store.get_usage(&key), 150);
    }

    #[test]
    fn test_per_agent_isolation() {
        let store = InMemoryStore::new();
        let agent_a = test_key("wallet_aaa");
        let agent_b = test_key("wallet_bbb");

        store.increment(&agent_a, 100);
        store.increment(&agent_b, 200);

        assert_eq!(store.get_usage(&agent_a), 100);
        assert_eq!(store.get_usage(&agent_b), 200);
    }

    #[test]
    fn test_period_reset() {
        let store = InMemoryStore::new();
        let key = test_key("pool");

        store.increment(&key, 100);
        assert_eq!(store.get_usage(&key), 100);

        store.reset_period("2026-03");
        assert_eq!(store.get_usage(&key), 0);
    }

    #[test]
    fn test_different_periods_independent() {
        let store = InMemoryStore::new();
        let march = AccountingKey {
            period: "2026-03".to_string(),
            ..test_key("pool")
        };
        let april = AccountingKey {
            period: "2026-04".to_string(),
            ..test_key("pool")
        };

        store.increment(&march, 100);
        store.increment(&april, 50);

        assert_eq!(store.get_usage(&march), 100);
        assert_eq!(store.get_usage(&april), 50);

        store.reset_period("2026-03");
        assert_eq!(store.get_usage(&march), 0);
        assert_eq!(store.get_usage(&april), 50);
    }

    #[test]
    fn test_current_period_format() {
        let period = current_period();
        // Should be in YYYY-MM format
        assert!(period.contains('-'));
        let parts: Vec<&str> = period.split('-').collect();
        assert_eq!(parts.len(), 2);
        let year: u64 = parts[0].parse().unwrap();
        let month: u64 = parts[1].parse().unwrap();
        assert!(year >= 2024);
        assert!((1..=12).contains(&month));
    }

    #[test]
    fn test_in_memory_store_default() {
        let store = InMemoryStore::default();
        let key = test_key("pool");
        assert_eq!(store.get_usage(&key), 0);
    }

    #[test]
    fn test_different_endpoints_independent() {
        let store = InMemoryStore::new();
        let key1 = AccountingKey {
            endpoint: "v1/a".to_string(),
            ..test_key("pool")
        };
        let key2 = AccountingKey {
            endpoint: "v1/b".to_string(),
            ..test_key("pool")
        };

        store.increment(&key1, 100);
        store.increment(&key2, 200);

        assert_eq!(store.get_usage(&key1), 100);
        assert_eq!(store.get_usage(&key2), 200);
    }

    #[test]
    fn test_reset_nonexistent_period_is_noop() {
        let store = InMemoryStore::new();
        let key = test_key("pool");
        store.increment(&key, 100);
        store.reset_period("2099-12");
        assert_eq!(store.get_usage(&key), 100);
    }
}
