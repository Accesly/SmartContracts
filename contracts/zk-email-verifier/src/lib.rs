#![no_std]

pub mod contract;
pub use contract::{
    VerifyingKey, ZkEmailProof, ZkEmailVerifier, ZkEmailVerifierClient, NUM_PUBLIC_SIGNALS,
};
