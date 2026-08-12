//! Transport-independent primitives for a `pay push` batch payout.
//!
//! Parsing and manifest construction happen before a wallet is unlocked. This
//! module deliberately does not know how a batch is signed or submitted.

pub mod manifest;
