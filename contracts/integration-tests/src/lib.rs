#![no_std]
//! # Accesly — Integration tests
//!
//! This crate holds cross-contract test scenarios that exercise multiple
//! Accesly contracts in the same `Env`. Per-contract unit tests live in each
//! contract's own `src/contract.rs`.
//!
//! Run with:
//!
//! ```bash
//! cargo test -p accesly-integration-tests
//! ```
//!
//! Tests live under `tests/`:
//! - `smart_account_construction.rs` — full Smart Account deploy wiring all
//!   real verifiers + policies (validates that the deploy script will work).
//! - `zk_recovery_hardfail.rs` — locks in the intentional `verify() = false`
//!   security decision documented in `Pendientes_Fase2.md`.
//!
//! The timelock 48h-delay flow is fully covered by the per-contract tests in
//! `contracts/governance/src/contract.rs` (see `execute_before_delay_fails`,
//! `execute_after_delay_succeeds`, `check_auth_rejects_unscheduled_operation`),
//! so an integration version would just duplicate them.
