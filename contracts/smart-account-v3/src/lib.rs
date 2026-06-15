#![no_std]
#![allow(clippy::too_many_arguments)]

pub mod context_rules;
pub mod contract;

// Los tests viven en `contracts/integration-tests/tests/smart_account_v3.rs`
// porque el constructor invoca `batch_canonicalize_key` en los verifiers, lo
// que requiere instancias reales (no Address::generate dummies).

pub use contract::{AcceslySmartAccountV3, AcceslySmartAccountV3Client};
