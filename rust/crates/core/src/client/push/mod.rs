//! Transport-independent primitives for a `pay push` batch payout, plus the
//! executor that drives them end to end.
//!
//! Parsing and manifest construction happen before a wallet is unlocked, and
//! `manifest`/`planner`/`permit`/`journal` deliberately don't know how a
//! batch is broadcast — that's `executor`'s job:
//!
//! - `manifest`: the canonical CSV manifest, content-hashed into a
//!   `batchId`.
//! - `planner`: read-only preflight and deterministic packing of manifest
//!   rows into chunks.
//! - `permit`: the one-approval signing permit
//!   ([`permit::BatchSigningPermit`]) — the only thing that ever touches the
//!   loaded signer.
//! - `journal`: the durable, fsync-before-broadcast event log and its resume
//!   reducer.
//! - `executor`: the bounded, backpressured pipeline
//!   ([`executor::PushExecutor`]) that pulls chunks from `planner`, signs
//!   them via `permit`, journals them, and broadcasts them through a
//!   pluggable [`executor::ChunkBroadcaster`] (direct-to-RPC for self-funded
//!   runs, pay-api's `/api/v1/transfer-batches` for gasless ones).

pub mod executor;
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
