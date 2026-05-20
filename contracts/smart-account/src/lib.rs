#![no_std]
// __constructor takes 13 params — required by the architecture (see contract.rs
// for the rationale). soroban_sdk::contractargs macro generates an args struct
// that re-triggers this lint, so we allow it crate-wide.
#![allow(clippy::too_many_arguments)]

pub mod context_rules;
pub mod contract;
pub mod trustlines;

pub use contract::{AcceslySmartAccount, AcceslySmartAccountClient};
pub use trustlines::StellarAsset;
