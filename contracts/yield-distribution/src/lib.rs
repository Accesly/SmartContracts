// @deprecated 2026-06-15 — fuera de scope por nuevo spec Accesly (recovery via OTP-email + sin yield interno + sin Blend).
// Mantenido en git history; excluido de workspace en Cargo.toml. Ver SDKAccesly/docs/Plan_Final_v1.md §10.

#![no_std]

pub mod contract;
pub use contract::{
    YieldConfig, YieldDistributionPolicy, YieldDistributionPolicyClient, YieldInstallParams,
    WEEK_IN_LEDGERS,
};
