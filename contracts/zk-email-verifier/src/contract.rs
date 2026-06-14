//! # Accesly — ZK Email Verifier (v2)
//!
//! Three on-chain roles:
//!
//! 1. **DKIM Registry** (unchanged from v1) — admin registers/revokes
//!    `(domain_hash, dkim_public_key_hash)` pairs from
//!    `stellar_zk_email::dkim_registry`.
//!
//! 2. **Groth16 verifier (BLS12-381)** — accepts a Groth16 proof produced
//!    by the `accesly-zkemail` circuit (Phase 2/4 of that repo) and runs
//!    `pairing_check` against the stored verifying key.
//!
//! 3. **Recovery binder (Almanax BL-01 mitigation)** — re-derives the
//!    semantically-bound hashes from the proof's public signals and checks
//!    them against the SmartAccount-provided `key_data` (the user's email
//!    commitment) and the SDK-provided `recovery_command` (a canonical
//!    string that binds the new passkey to the wallet). Without these
//!    bindings, a valid proof for one user could be replayed to take
//!    over another wallet — the original DKIM-only check that BL-01
//!    flagged. The nullifier registry blocks proof replay across calls.
//!
//! ## Public signals layout (D1 option C, accesly-zkemail)
//!
//! 14 signals, each `BytesN<32>`, in pairs `[low, high]` per BLS12-381
//! field constraint:
//!
//! | Index | Meaning |
//! |---:|---|
//! | 0, 1 | `recipient_email_hash` — must equal `key_data` (email commitment) |
//! | 2, 3 | `dkim_public_key_hash` — must be a registered DKIM key for `domain_hash` |
//! | 4, 5 | `email_nullifier` — must be unique across the contract's nullifier set |
//! | 6, 7 | `command_hash` — must equal `sha256(recovery_command)` |
//! | 8, 9 | `date_header_hash` (reserved) |
//! | 10, 11 | `sender_hash` (reserved) |
//! | 12, 13 | `from_domain_hash` (reserved, zero in Phase 1) |
//!
//! ## Verification equation
//!
//! Groth16's pairing check, rearranged so negations live in the VK
//! (`alpha_neg`, `gamma_neg`, `delta_neg` pre-computed off-chain by
//! `accesly-zkemail/rust-verifier/scripts/export_vk.ts`):
//!
//! ```text
//!   e(A, B) · e(-α, β) · e(vk_x, -γ) · e(C, -δ) = 1
//! ```
//!
//! where `vk_x = IC[0] + Σᵢ public_signal[i] · IC[i+1]` (computed via the
//! `g1_msm` host function).
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    crypto::bls12_381::{Bls12381G1Affine as G1, Bls12381G2Affine as G2, Fr},
    panic_with_error,
    xdr::FromXdr,
    Address, Bytes, BytesN, Env, Symbol, Vec,
};
use stellar_access::access_control::{get_admin, set_admin, AccessControl};
use stellar_accounts::verifiers::Verifier;
use stellar_zk_email::dkim_registry::{self, DKIMRegistry};

/// 7 signals × `[low, high]`, per D1 option C of accesly-zkemail.
pub const NUM_PUBLIC_SIGNALS: u32 = 14;

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum ZkVerifierError {
    AlreadyInitialized = 100,
    NotInitialized = 101,
    InvalidVkShape = 102,
}

// ── Storage ───────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
enum StorageKey {
    Vk,
    /// Per-proof anti-replay flag. Persistent so an attacker can never re-use
    /// a previously-burned nullifier even after instance TTL bumps.
    Nullifier(BytesN<32>),
}

/// Groth16 verifying key, BLS12-381 uncompressed.
///
/// `alpha_neg`, `gamma_neg`, `delta_neg` are pre-computed off-chain so the
/// on-chain `verify` does zero point negations per proof. See the module
/// docs for the bilinear identity that makes this safe.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct VerifyingKey {
    /// -α in G1, 96 uncompressed bytes.
    pub alpha_neg: BytesN<96>,
    /// β in G2, 192 uncompressed bytes.
    pub beta: BytesN<192>,
    /// -γ in G2.
    pub gamma_neg: BytesN<192>,
    /// -δ in G2.
    pub delta_neg: BytesN<192>,
    /// IC[0..NUM_PUBLIC_SIGNALS] in G1. Must have exactly
    /// `NUM_PUBLIC_SIGNALS + 1 = 15` entries.
    pub ic: Vec<BytesN<96>>,
}

// ── Proof payload (XDR-encoded inside sig_data) ──────────────────────────────

/// Payload that the SDK serializes (XDR) and passes as `sig_data` to the
/// verifier. The proof's Groth16 components live alongside the public
/// signals and the semantic bindings the contract needs to re-derive.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ZkEmailProof {
    /// Groth16 A in G1, 96 uncompressed bytes.
    pub a: BytesN<96>,
    /// Groth16 B in G2, 192 uncompressed bytes.
    pub b: BytesN<192>,
    /// Groth16 C in G1.
    pub c: BytesN<96>,
    /// Public signals from the circuit, 14 × 32 bytes (low/high pairs).
    pub public_signals: Vec<BytesN<32>>,
    /// SHA-256 of the email's "From" domain (e.g. `gmail.com`). Used to
    /// look up the DKIM key in the registry — must match a registered
    /// `(domain_hash, dkim_public_key_hash)` pair.
    pub domain_hash: BytesN<32>,
    /// Canonical recovery command string the user wrote in the email
    /// subject, exactly: `"Accesly Recovery: <wallet> -> <new_passkey>"`.
    /// The contract checks `sha256(recovery_command) == command_hash` from
    /// public signals 6 + 7, which binds the proof to the specific
    /// `(wallet, new_passkey)` pair the SmartAccount is rotating to.
    pub recovery_command: Bytes,
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct ZkEmailVerifier;

#[contractimpl]
impl ZkEmailVerifier {
    /// Initializes the verifier with an admin and the Groth16 verifying
    /// key. Cannot be re-initialized.
    pub fn __constructor(e: &Env, admin: Address, vk: VerifyingKey) {
        if get_admin(e).is_some() {
            panic_with_error!(e, ZkVerifierError::AlreadyInitialized);
        }
        validate_vk_shape(e, &vk);
        set_admin(e, &admin);
        e.storage().instance().set(&StorageKey::Vk, &vk);
    }

    /// Returns the stored VK. Useful for off-chain monitoring tools that
    /// want to confirm the contract was bootstrapped with the expected
    /// ceremony output.
    pub fn vk(e: &Env) -> VerifyingKey {
        e.storage()
            .instance()
            .get(&StorageKey::Vk)
            .unwrap_or_else(|| panic_with_error!(e, ZkVerifierError::NotInitialized))
    }

    /// Rotates the VK. Restricted to admin. Use this after a real
    /// (multi-party) ceremony if the testnet VK was provisional.
    pub fn set_vk(e: &Env, new_vk: VerifyingKey) {
        require_admin(e);
        validate_vk_shape(e, &new_vk);
        e.storage().instance().set(&StorageKey::Vk, &new_vk);
    }

    /// True iff `nullifier` has already been consumed by a successful
    /// `verify`. Useful for off-chain replay-attempt monitoring; the
    /// contract itself enforces uniqueness internally during `verify`.
    pub fn is_nullifier_used(e: &Env, nullifier: BytesN<32>) -> bool {
        e.storage()
            .persistent()
            .has(&StorageKey::Nullifier(nullifier))
    }
}

// ── DKIM registry (unchanged from v1) ────────────────────────────────────────

#[contractimpl]
impl DKIMRegistry for ZkEmailVerifier {
    fn set_dkim_public_key_hash(
        e: &Env,
        domain_hash: BytesN<32>,
        public_key_hash: BytesN<32>,
        operator: Address,
    ) {
        require_admin(e);
        dkim_registry::set_dkim_public_key_hash(e, &domain_hash, &public_key_hash);
        let _ = operator;
    }

    fn set_dkim_public_key_hashes(
        e: &Env,
        domain_hash: BytesN<32>,
        public_key_hashes: Vec<BytesN<32>>,
        operator: Address,
    ) {
        require_admin(e);
        for pk_hash in public_key_hashes.iter() {
            dkim_registry::set_dkim_public_key_hash(e, &domain_hash, &pk_hash);
        }
        let _ = operator;
    }

    fn revoke_dkim_public_key_hash(e: &Env, public_key_hash: BytesN<32>, operator: Address) {
        require_admin(e);
        dkim_registry::revoke_dkim_public_key_hash(e, &public_key_hash);
        let _ = operator;
    }
}

// ── Verifier (Almanax-bound Groth16 check) ───────────────────────────────────

#[contractimpl]
impl Verifier for ZkEmailVerifier {
    /// 32-byte email commitment stored in the SmartAccount at deploy. The
    /// `verify` function checks that the proof's `recipient_email_hash`
    /// signal (signals 0 + 1) equals this commitment, binding the proof to
    /// the wallet's owner email.
    type KeyData = BytesN<32>;

    /// XDR-encoded `ZkEmailProof` (defined above).
    type SigData = Bytes;

    /// Verifies a Groth16 proof, the DKIM-registry membership of its
    /// public key, the recovery-command binding, and the email-commitment
    /// binding — exactly the four checks Almanax BL-01 (2026-04-27) called
    /// out as missing. Burns the proof's nullifier to prevent replay.
    ///
    /// Returns `true` only when all five checks pass:
    ///   1. `public_signals.len() == 14`
    ///   2. `recipient_email_hash` (signals 0+1) `== key_data`
    ///   3. `(domain_hash, dkim_pk_hash)` registered + not revoked
    ///   4. `command_hash` (signals 6+7) `== sha256(recovery_command)`
    ///   5. `email_nullifier` (signals 4+5) not seen before (and is burned)
    ///   6. Groth16 pairing equation holds for the stored VK
    fn verify(
        e: &Env,
        _signature_payload: Bytes,
        key_data: BytesN<32>,
        sig_data: Bytes,
    ) -> bool {
        let proof = match parse_sig_data(e, &sig_data) {
            Some(p) => p,
            None => return false,
        };

        if proof.public_signals.len() != NUM_PUBLIC_SIGNALS {
            return false;
        }

        // (2) email-commitment binding.
        let recipient_email_hash = combine_low_high(
            e,
            &proof.public_signals.get_unchecked(0),
            &proof.public_signals.get_unchecked(1),
        );
        if recipient_email_hash != key_data {
            return false;
        }

        // (3) DKIM registry: the key the email was signed with must be a
        // currently-valid Accesly-trusted key.
        let dkim_pk_hash = combine_low_high(
            e,
            &proof.public_signals.get_unchecked(2),
            &proof.public_signals.get_unchecked(3),
        );
        if !dkim_registry::is_key_hash_valid(e, &proof.domain_hash, &dkim_pk_hash) {
            return false;
        }
        if dkim_registry::is_key_hash_revoked(e, &dkim_pk_hash) {
            return false;
        }

        // (4) recovery-command binding: the proof commits to the exact
        // canonical command string the user wrote in the email subject.
        let command_hash = combine_low_high(
            e,
            &proof.public_signals.get_unchecked(6),
            &proof.public_signals.get_unchecked(7),
        );
        let expected_command_hash: BytesN<32> = e.crypto().sha256(&proof.recovery_command).into();
        if command_hash != expected_command_hash {
            return false;
        }

        // (5) replay guard. Done BEFORE the pairing check so a fresh nullifier
        // is only burned if we expect the proof to actually verify.
        let nullifier = combine_low_high(
            e,
            &proof.public_signals.get_unchecked(4),
            &proof.public_signals.get_unchecked(5),
        );
        if e.storage()
            .persistent()
            .has(&StorageKey::Nullifier(nullifier.clone()))
        {
            return false;
        }

        // (6) Groth16 pairing check.
        if !groth16_pairing_check(e, &proof) {
            return false;
        }

        // All checks passed — burn the nullifier.
        e.storage()
            .persistent()
            .set(&StorageKey::Nullifier(nullifier), &true);

        true
    }

    fn canonicalize_key(e: &Env, key_data: BytesN<32>) -> Bytes {
        Bytes::from_slice(e, &key_data.to_array())
    }

    fn batch_canonicalize_key(e: &Env, keys_data: Vec<BytesN<32>>) -> Vec<Bytes> {
        Vec::from_iter(
            e,
            keys_data
                .iter()
                .map(|k| Bytes::from_slice(e, &k.to_array())),
        )
    }
}

// ── AccessControl + queries (unchanged from v1) ──────────────────────────────

#[contractimpl(contracttrait)]
impl AccessControl for ZkEmailVerifier {}

#[contractimpl]
impl ZkEmailVerifier {
    pub fn is_dkim_valid(e: Env, domain_hash: BytesN<32>, public_key_hash: BytesN<32>) -> bool {
        dkim_registry::is_key_hash_valid(&e, &domain_hash, &public_key_hash)
    }

    pub fn is_dkim_revoked(e: Env, public_key_hash: BytesN<32>) -> bool {
        dkim_registry::is_key_hash_revoked(&e, &public_key_hash)
    }
}

// ── Internals ────────────────────────────────────────────────────────────────

fn require_admin(e: &Env) {
    get_admin(e).expect("admin not set").require_auth();
}

fn validate_vk_shape(e: &Env, vk: &VerifyingKey) {
    if vk.ic.len() != NUM_PUBLIC_SIGNALS + 1 {
        panic_with_error!(e, ZkVerifierError::InvalidVkShape);
    }
}

/// Decodes the XDR-encoded `ZkEmailProof` payload from `sig_data`.
/// Returns `None` if decoding fails (malformed payload → verify returns false).
fn parse_sig_data(e: &Env, sig_data: &Bytes) -> Option<ZkEmailProof> {
    ZkEmailProof::from_xdr(e, sig_data).ok()
}

/// Combines two 32-byte limbs `[low, high]` from the circuit's BLS12-381
/// field-friendly representation into a single 32-byte SHA-256-style hash.
///
/// The circuit splits a 256-bit hash into two 128-bit chunks so each fits
/// inside the BLS12-381 scalar field (255-bit `Fr`). Reconstruction:
///
/// ```text
///   hash[0..16] = high[16..32]
///   hash[16..32] = low[16..32]
/// ```
///
/// (each chunk uses the low 128 bits of its 32-byte BE encoding).
fn combine_low_high(e: &Env, low: &BytesN<32>, high: &BytesN<32>) -> BytesN<32> {
    let low_arr = low.to_array();
    let high_arr = high.to_array();
    let mut out = [0u8; 32];
    // Top 16 bytes of `high`'s low-128 chunk.
    out[..16].copy_from_slice(&high_arr[16..]);
    // Bottom 16 bytes from `low`'s low-128 chunk.
    out[16..].copy_from_slice(&low_arr[16..]);
    BytesN::from_array(e, &out)
}

/// Pure pairing check using the stored VK. `vk_x` is computed via `g1_msm`
/// over the 14 public signals.
fn groth16_pairing_check(e: &Env, proof: &ZkEmailProof) -> bool {
    let vk: VerifyingKey = e
        .storage()
        .instance()
        .get(&StorageKey::Vk)
        .unwrap_or_else(|| panic_with_error!(e, ZkVerifierError::NotInitialized));

    let bls = e.crypto().bls12_381();

    // vk_x = IC[0] + Σᵢ IC[i+1] · public_signal[i]
    let mut msm_points = Vec::new(e);
    let mut msm_scalars = Vec::new(e);
    for i in 0..proof.public_signals.len() {
        let ic_i_plus_1 = G1::from_bytes(vk.ic.get_unchecked(i + 1));
        let signal = Fr::from_bytes(proof.public_signals.get_unchecked(i));
        msm_points.push_back(ic_i_plus_1);
        msm_scalars.push_back(signal);
    }
    let weighted = bls.g1_msm(msm_points, msm_scalars);
    let ic_zero = G1::from_bytes(vk.ic.get_unchecked(0));
    let vk_x = bls.g1_add(&ic_zero, &weighted);

    // Multi-pairing: e(A, B) · e(-α, β) · e(vk_x, -γ) · e(C, -δ) ?= 1.
    let mut g1_vec = Vec::new(e);
    let mut g2_vec = Vec::new(e);

    g1_vec.push_back(G1::from_bytes(proof.a.clone()));
    g2_vec.push_back(G2::from_bytes(proof.b.clone()));

    g1_vec.push_back(G1::from_bytes(vk.alpha_neg));
    g2_vec.push_back(G2::from_bytes(vk.beta));

    g1_vec.push_back(vk_x);
    g2_vec.push_back(G2::from_bytes(vk.gamma_neg));

    g1_vec.push_back(G1::from_bytes(proof.c.clone()));
    g2_vec.push_back(G2::from_bytes(vk.delta_neg));

    bls.pairing_check(g1_vec, g2_vec)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
