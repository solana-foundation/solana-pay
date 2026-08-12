//! Transport-independent primitives for a `pay push` batch payout.
//!
//! Parsing and manifest construction happen before a wallet is unlocked. This
//! module deliberately does not know how a batch is signed or submitted.
//!
//! Slice 2 delivers the CSV manifest (`manifest`), read-only preflight and
//! deterministic packing (`planner`), the one-approval signing permit
//! (`permit`), and the durable, fsync-before-broadcast journal (`journal`).
//! Broadcast/confirm execution (`executor`, `direct`, `gasless`) is a later
//! slice — nothing in this module performs network I/O other than the
//! explicitly read-only preflight RPC lookups described in the plan.

pub mod journal;
pub mod manifest;
pub mod permit;
pub mod planner;

/// Number of leading hex characters of a manifest's BLAKE3 hash used
/// everywhere a compact, human-scannable identifier is needed: the
/// per-chunk on-chain memo (`pay-push:v1:<prefix>:<chunk-index>`) and the
/// default journal file name
/// (`~/.config/pay/push/<UTC timestamp>-<prefix>.jsonl`).
pub const MANIFEST_HASH_PREFIX_LEN: usize = 8;

/// Slice a manifest's full 64-character BLAKE3 hex digest
/// ([`manifest::TransferManifest::hash_hex`]) down to
/// [`MANIFEST_HASH_PREFIX_LEN`] characters.
pub fn manifest_hash_prefix(hash_hex: &str) -> &str {
    let end = hash_hex.len().min(MANIFEST_HASH_PREFIX_LEN);
    &hash_hex[..end]
}
