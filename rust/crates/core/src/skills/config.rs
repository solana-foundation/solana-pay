//! Local skills configuration — `~/.config/pay/skills.yaml`.
//!
//! Tracks provider sources (catalog URLs or GitHub repos) and cache
//! settings. `pay install` / `pay skills add` / `pay skills remove`
//! mutate this file.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

const SKILLS_CONFIG_FILE: &str = "~/.config/pay/skills.yaml";
const SKILLS_CACHE_DIR: &str = "~/.config/pay/skills";

/// Default cache TTL in minutes.
const DEFAULT_TTL_MINUTES: u32 = 30;

/// The default catalog shipped with pay — always present even if the
/// user hasn't added any sources.
pub const DEFAULT_SOURCE: &str = "https://catalog.pay.sh/v1/skills.json";

/// A provider source in the skills catalog config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    /// Display name (e.g. "google", "company/apis").
    pub name: String,
    /// Resolved URL to the catalog JSON.
    pub url: String,
    /// Marks a transient source — currently the auto-registration written
    /// by a running `pay gate api` so the local API is discoverable
    /// by an MCP agent on the same host. Ephemeral entries are TCP-probed
    /// at boot and reaped if their server is gone, and the catalog loader
    /// bypasses cache for them so live edits to the server's spec become
    /// visible on the next agent call without waiting on the 30 min TTL.
    #[serde(default, skip_serializing_if = "is_false")]
    pub ephemeral: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillsConfig {
    /// Cache time-to-live in minutes.
    #[serde(default = "default_ttl")]
    pub ttl_minutes: u32,
    #[serde(default)]
    pub sources: Vec<Source>,
}

fn default_ttl() -> u32 {
    DEFAULT_TTL_MINUTES
}

impl Default for SkillsConfig {
    fn default() -> Self {
        Self {
            ttl_minutes: DEFAULT_TTL_MINUTES,
            sources: vec![Source {
                name: "pay-skills".to_string(),
                url: DEFAULT_SOURCE.to_string(),
                ephemeral: false,
            }],
        }
    }
}

impl SkillsConfig {
    pub fn load() -> Result<Self> {
        let path = config_path();
        if !path.exists()
            || std::fs::read_to_string(&path)
                .map(|r| r.trim().is_empty())
                .unwrap_or(true)
        {
            let cfg = Self::default();
            let _ = cfg.save(); // persist so the user can see/edit it
            return Ok(cfg);
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
        serde_yml::from_str(&raw)
            .map_err(|e| Error::Config(format!("parse {}: {e}", path.display())))
    }

    pub fn save(&self) -> Result<()> {
        let path = config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::Config(format!("mkdir: {e}")))?;
        }
        let yaml =
            serde_yml::to_string(self).map_err(|e| Error::Config(format!("serialize: {e}")))?;
        std::fs::write(&path, yaml)
            .map_err(|e| Error::Config(format!("write {}: {e}", path.display())))
    }

    /// Add a source. Returns true if it was new.
    pub fn add_source(&mut self, source: &str) -> bool {
        let url = resolve_source_url(source);
        if self.sources.iter().any(|s| s.url == url) {
            return false;
        }
        self.sources.push(Source {
            name: derive_name(source),
            url,
            ephemeral: false,
        });
        true
    }

    /// Add a source marked as ephemeral (auto-removed on graceful shutdown,
    /// reaped at boot if its server isn't reachable). Caller supplies the
    /// display `name` so multiple concurrent `pay gate api` instances
    /// don't collide on the URL-derived default. Returns true if new.
    pub fn add_ephemeral_source(&mut self, name: &str, url: &str) -> bool {
        if self.sources.iter().any(|s| s.url == url) {
            return false;
        }
        self.sources.push(Source {
            name: name.to_string(),
            url: url.to_string(),
            ephemeral: true,
        });
        true
    }

    /// Remove a source by name or URL. Returns true if it existed.
    pub fn remove_source(&mut self, source: &str) -> bool {
        let url = resolve_source_url(source);
        let before = self.sources.len();
        self.sources.retain(|s| s.url != url && s.name != source);
        self.sources.len() < before
    }

    /// Remove a source by exact URL match (no github-shorthand resolution).
    /// Used by the ephemeral lifecycle hooks so they don't accidentally
    /// rewrite a `company/apis` shorthand source registered by the user.
    pub fn remove_source_by_url(&mut self, url: &str) -> bool {
        let before = self.sources.len();
        self.sources.retain(|s| s.url != url);
        self.sources.len() < before
    }

    /// Borrow the ephemeral sources for boot-time liveness sweeps.
    pub fn ephemeral_sources(&self) -> impl Iterator<Item = &Source> {
        self.sources.iter().filter(|s| s.ephemeral)
    }

    /// True when at least one ephemeral source is registered. Catalog
    /// callers use this to skip the on-disk cache and re-fetch every
    /// load — ephemeral specs change as the developer edits + restarts
    /// `pay gate api`, and a 30 min TTL would hide those edits from the
    /// MCP agent in the same shell.
    pub fn has_ephemeral_sources(&self) -> bool {
        self.sources.iter().any(|s| s.ephemeral)
    }

    /// Deterministic 8-hex-char hash of the sorted source URLs.
    /// Changes when sources are added/removed, invalidating the cache.
    pub fn sources_hash(&self) -> String {
        let mut sorted: Vec<_> = self.sources.iter().map(|s| &s.url).collect();
        sorted.sort();
        let mut hasher = DefaultHasher::new();
        sorted.hash(&mut hasher);
        format!("{:016x}", hasher.finish())[..8].to_string()
    }

    /// Get source URLs for fetching.
    pub fn source_urls(&self) -> Vec<&str> {
        self.sources.iter().map(|s| s.url.as_str()).collect()
    }

    /// Path to the current valid cache file, or None if stale/missing.
    pub fn valid_cache_path(&self) -> Option<PathBuf> {
        let dir = cache_dir();
        let hash = self.sources_hash();
        // Look for a cache file matching this hash
        let entries = std::fs::read_dir(&dir).ok()?;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("skills-") && name.contains(&hash) && name.ends_with(".json") {
                // Check TTL
                if let Ok(meta) = entry.metadata()
                    && let Ok(modified) = meta.modified()
                {
                    let age = modified
                        .elapsed()
                        .unwrap_or(std::time::Duration::from_secs(u64::MAX));
                    if age.as_secs() < (self.ttl_minutes as u64) * 60 {
                        return Some(entry.path());
                    }
                }
            }
        }
        None
    }

    /// Generate a new cache file path for the current source list.
    pub fn new_cache_path(&self) -> PathBuf {
        let dir = cache_dir();
        let hash = self.sources_hash();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        dir.join(format!("skills-{ts}-{hash}.json"))
    }

    /// Remove every `skills-*.json` cache file except `keep`.
    ///
    /// Catalog files are timestamped, so even with an unchanged source hash
    /// each successful update writes a new file. Without this prune, repeat
    /// `pay skills update` calls would accumulate one stale catalog per run.
    pub fn clean_stale_caches(&self, keep: &std::path::Path) {
        let dir = cache_dir();
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path == keep {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("skills-") && name.ends_with(".json") {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

/// Resolve a source shorthand to a URL.
fn resolve_source_url(source: &str) -> String {
    if source.starts_with("http://") || source.starts_with("https://") {
        return source.to_string();
    }
    if source.contains('/') && !source.contains(' ') {
        return format!(
            "https://raw.githubusercontent.com/{}/main/catalog.json",
            source
        );
    }
    source.to_string()
}

/// Derive a short display name from a source string.
/// - `company/apis` → `company/apis`
/// - `https://storage.googleapis.com/.../google/sandbox.json` → `google`
/// - `https://example.com/catalog.json` → `example.com`
fn derive_name(source: &str) -> String {
    // GitHub shorthand — keep as-is, it's already a good name.
    if !source.starts_with("http://") && !source.starts_with("https://") {
        return source.to_string();
    }
    // Try to extract a meaningful segment from the URL path.
    if let Some(path) = source.split("//").nth(1) {
        let segments: Vec<&str> = path
            .split('/')
            .filter(|s| !s.is_empty() && *s != "catalog.json" && *s != "sandbox.json")
            .collect();
        // Use the last meaningful path segment before the filename.
        if let Some(last) = segments.last()
            && (!last.contains('.') || segments.len() <= 2)
        {
            return last.to_string();
        }
        // Fall back to the hostname.
        if let Some(host) = segments.first() {
            return host.to_string();
        }
    }
    source.to_string()
}

fn config_path() -> PathBuf {
    PathBuf::from(shellexpand::tilde(SKILLS_CONFIG_FILE).into_owned())
}

fn cache_dir() -> PathBuf {
    PathBuf::from(shellexpand::tilde(SKILLS_CACHE_DIR).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_default_source() {
        let cfg = SkillsConfig::default();
        assert_eq!(cfg.sources.len(), 1);
        assert_eq!(cfg.sources[0].name, "pay-skills");
        assert_eq!(cfg.sources[0].url, DEFAULT_SOURCE);
        assert!(!cfg.sources[0].ephemeral);
    }

    #[test]
    fn add_source_deduplicates() {
        let mut cfg = SkillsConfig::default();
        assert!(cfg.add_source("https://example.com/catalog.json"));
        assert!(!cfg.add_source("https://example.com/catalog.json"));
        assert_eq!(cfg.sources.len(), 2);
    }

    #[test]
    fn add_source_resolves_github_shorthand() {
        let mut cfg = SkillsConfig::default();
        cfg.add_source("company/apis");
        let last = cfg.sources.last().unwrap();
        assert_eq!(last.name, "company/apis");
        assert!(last.url.contains("raw.githubusercontent.com"));
    }

    #[test]
    fn remove_source_by_url() {
        let mut cfg = SkillsConfig::default();
        cfg.add_source("https://example.com/catalog.json");
        assert!(cfg.remove_source("https://example.com/catalog.json"));
        assert!(!cfg.remove_source("https://example.com/catalog.json"));
    }

    #[test]
    fn remove_source_by_name() {
        let mut cfg = SkillsConfig::default();
        cfg.add_source("company/apis");
        assert!(cfg.remove_source("company/apis"));
        assert_eq!(cfg.sources.len(), 1); // only default left
    }

    #[test]
    fn sources_hash_is_deterministic() {
        let mut cfg = SkillsConfig::default();
        cfg.add_source("https://a.com");
        cfg.add_source("https://b.com");
        let h1 = cfg.sources_hash();
        cfg.sources.reverse();
        let h2 = cfg.sources_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn sources_hash_changes_on_add() {
        let cfg1 = SkillsConfig::default();
        let mut cfg2 = SkillsConfig::default();
        cfg2.add_source("https://new.com");
        assert_ne!(cfg1.sources_hash(), cfg2.sources_hash());
    }

    #[test]
    fn resolve_source_github_shorthand() {
        let url = resolve_source_url("company/my-apis");
        assert_eq!(
            url,
            "https://raw.githubusercontent.com/company/my-apis/main/catalog.json"
        );
    }

    #[test]
    fn resolve_source_full_url_passthrough() {
        let url = resolve_source_url("https://example.com/foo.json");
        assert_eq!(url, "https://example.com/foo.json");
    }

    #[test]
    fn derive_name_github_shorthand() {
        assert_eq!(derive_name("company/apis"), "company/apis");
    }

    #[test]
    fn derive_name_gcs_url() {
        assert_eq!(
            derive_name("https://storage.googleapis.com/bucket/catalog/google/sandbox.json"),
            "google"
        );
    }

    #[test]
    fn derive_name_simple_url() {
        assert_eq!(
            derive_name("https://example.com/catalog.json"),
            "example.com"
        );
    }

    #[test]
    fn source_urls_returns_all_urls() {
        let mut cfg = SkillsConfig::default();
        cfg.add_source("https://a.com/catalog.json");
        cfg.add_source("https://b.com/catalog.json");
        let urls = cfg.source_urls();
        assert_eq!(urls.len(), 3); // default + 2
        assert!(urls.contains(&"https://a.com/catalog.json"));
        assert!(urls.contains(&"https://b.com/catalog.json"));
    }

    #[test]
    fn new_cache_path_contains_hash() {
        let cfg = SkillsConfig::default();
        let hash = cfg.sources_hash();
        let path = cfg.new_cache_path();
        let filename = path.file_name().unwrap().to_string_lossy();
        assert!(filename.starts_with("skills-"));
        assert!(filename.contains(&hash));
        assert!(filename.ends_with(".json"));
    }

    #[test]
    fn valid_cache_path_returns_none_when_no_cache() {
        // With no cache dir, should return None
        let mut cfg = SkillsConfig::default();
        // Add a unique source so hash won't match any existing cache
        cfg.add_source("https://unique-test-source-12345.example.com/catalog.json");
        // valid_cache_path scans the cache dir — with a unique hash it won't find anything
        // (unless the dir doesn't exist, which also returns None)
        assert!(cfg.valid_cache_path().is_none());
    }

    #[test]
    fn clean_stale_caches_is_safe_when_dir_missing() {
        // Should not panic when cache dir doesn't exist
        let mut cfg = SkillsConfig::default();
        cfg.add_source("https://nonexistent-test-12345.example.com/catalog.json");
        cfg.clean_stale_caches(std::path::Path::new("/nonexistent/keep.json"));
    }

    #[test]
    fn default_ttl_value() {
        assert_eq!(default_ttl(), 30);
    }
}
