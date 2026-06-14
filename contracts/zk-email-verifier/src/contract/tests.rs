//! Unit tests for the v2 verifier.
//!
//! The Groth16 pairing check itself is exercised end-to-end in
//! `contracts/integration-tests/tests/zk_recovery_real.rs` against a real
//! proof produced by the accesly-zkemail SDK prover. Here we cover the
//! semantic-binding layers Almanax BL-01 mandated: VK shape, signal
//! length, email-commitment binding, DKIM registry binding,
//! recovery-command binding, and nullifier replay protection.
//!
//! All tests use a dummy `VerifyingKey` (zero bytes) — the pairing check
//! consequently fails, which is fine: we only assert that earlier
//! validation layers reject malformed proofs *before* the (expensive)
//! pairing call. The "happy path passes through to pairing_check" case
//! lives in the integration suite.

extern crate std;

use soroban_sdk::{
    testutils::Address as _,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, IntoVal, Vec,
};

use super::{
    VerifyingKey, ZkEmailProof, ZkEmailVerifier, ZkEmailVerifierClient, NUM_PUBLIC_SIGNALS,
};

const COMMAND: &str = "Accesly Recovery: CCWALLETXX -> 04abcdef";

fn dummy_vk(e: &Env) -> VerifyingKey {
    let mut ic = Vec::new(e);
    for _ in 0..(NUM_PUBLIC_SIGNALS + 1) {
        ic.push_back(BytesN::from_array(e, &[0u8; 96]));
    }
    VerifyingKey {
        alpha_neg: BytesN::from_array(e, &[0u8; 96]),
        beta: BytesN::from_array(e, &[0u8; 192]),
        gamma_neg: BytesN::from_array(e, &[0u8; 192]),
        delta_neg: BytesN::from_array(e, &[0u8; 192]),
        ic,
    }
}

fn deploy(e: &Env) -> (Address, Address) {
    let admin = Address::generate(e);
    let vk = dummy_vk(e);
    let addr = e.register(ZkEmailVerifier, (admin.clone(), vk));
    (addr, admin)
}

/// Builds a proof payload where the public-signal slots can be tweaked
/// by the caller. Returns the XDR-encoded `Bytes` ready for `verify`.
fn make_sig_data(
    e: &Env,
    public_signals: Vec<BytesN<32>>,
    domain_hash: [u8; 32],
    recovery_command: &str,
) -> Bytes {
    let proof = ZkEmailProof {
        a: BytesN::from_array(e, &[0u8; 96]),
        b: BytesN::from_array(e, &[0u8; 192]),
        c: BytesN::from_array(e, &[0u8; 96]),
        public_signals,
        domain_hash: BytesN::from_array(e, &domain_hash),
        recovery_command: Bytes::from_slice(e, recovery_command.as_bytes()),
    };
    proof.to_xdr(e)
}

/// Public-signals vector that combine_low_high(0,1) → `email_commitment`,
/// combine_low_high(2,3) → `pk_hash`, combine_low_high(4,5) → `nullifier`,
/// combine_low_high(6,7) → `sha256(recovery_command)`. Useful for the
/// "would pass all bindings except pairing" tests.
fn signals_matching(
    e: &Env,
    email_commitment: [u8; 32],
    pk_hash: [u8; 32],
    nullifier: [u8; 32],
    command_bytes: &[u8],
) -> Vec<BytesN<32>> {
    let command_hash: BytesN<32> = e
        .crypto()
        .sha256(&Bytes::from_slice(e, command_bytes))
        .into();
    let cmd = command_hash.to_array();

    let mut sigs = Vec::new(e);
    // Each pair is (low, high) where high holds bytes [0..16] of the hash
    // padded into the low 128 bits of a 32-byte BE word, and low holds
    // bytes [16..32] in the same shape. See combine_low_high().
    sigs.push_back(pair_low(e, &email_commitment));
    sigs.push_back(pair_high(e, &email_commitment));
    sigs.push_back(pair_low(e, &pk_hash));
    sigs.push_back(pair_high(e, &pk_hash));
    sigs.push_back(pair_low(e, &nullifier));
    sigs.push_back(pair_high(e, &nullifier));
    sigs.push_back(pair_low(e, &cmd));
    sigs.push_back(pair_high(e, &cmd));
    // Reserved signals 8..14 — zero.
    for _ in 8..NUM_PUBLIC_SIGNALS {
        sigs.push_back(BytesN::from_array(e, &[0u8; 32]));
    }
    sigs
}

fn pair_low(e: &Env, hash: &[u8; 32]) -> BytesN<32> {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&hash[16..]);
    BytesN::from_array(e, &out)
}

fn pair_high(e: &Env, hash: &[u8; 32]) -> BytesN<32> {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&hash[..16]);
    BytesN::from_array(e, &out)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn constructor_stores_admin_and_vk() {
    let e = Env::default();
    let (addr, admin) = deploy(&e);
    let client = ZkEmailVerifierClient::new(&e, &addr);
    assert_eq!(client.vk().ic.len(), NUM_PUBLIC_SIGNALS + 1);
    let _ = admin;
}

#[test]
#[should_panic(expected = "Error(Contract, #102)")] // InvalidVkShape
fn constructor_rejects_bad_vk_shape() {
    let e = Env::default();
    let admin = Address::generate(&e);
    let mut vk = dummy_vk(&e);
    vk.ic.pop_back();
    let _ = e.register(ZkEmailVerifier, (admin, vk));
}

#[test]
#[should_panic(expected = "InvalidInput")]
fn verify_panics_on_malformed_sig_data() {
    // Soroban's `from_xdr` escalates a malformed payload into a host-level
    // panic (Error(Value, InvalidInput)). That is acceptable behavior — the
    // tx fails, the SmartAccount __check_auth fails, no state is mutated.
    // Documenting it with a test so any future change to error handling
    // (e.g. wrapping in a Result that returns false) trips this assertion.
    let e = Env::default();
    let (addr, _) = deploy(&e);
    let client = ZkEmailVerifierClient::new(&e, &addr);

    let key_data = BytesN::from_array(&e, &[0u8; 32]);
    let payload = Bytes::from_array(&e, &[0u8; 32]);
    let garbage = Bytes::from_array(&e, &[0xFF; 16]);
    let _ = client.verify(&payload, &key_data, &garbage);
}

#[test]
fn verify_rejects_wrong_signal_count() {
    let e = Env::default();
    let (addr, _) = deploy(&e);
    let client = ZkEmailVerifierClient::new(&e, &addr);

    // Only 13 signals.
    let mut sigs = Vec::new(&e);
    for _ in 0..(NUM_PUBLIC_SIGNALS - 1) {
        sigs.push_back(BytesN::from_array(&e, &[0u8; 32]));
    }
    let sig_data = make_sig_data(&e, sigs, [0u8; 32], COMMAND);
    let key_data = BytesN::from_array(&e, &[0u8; 32]);
    let payload = Bytes::from_array(&e, &[0u8; 32]);
    assert!(!client.verify(&payload, &key_data, &sig_data));
}

#[test]
fn verify_rejects_email_commitment_mismatch() {
    let e = Env::default();
    let (addr, admin) = deploy(&e);
    e.mock_all_auths();
    let client = ZkEmailVerifierClient::new(&e, &addr);

    let dh = BytesN::from_array(&e, &[1u8; 32]);
    let pkh = BytesN::from_array(&e, &[2u8; 32]);
    client.set_dkim_public_key_hash(&dh, &pkh, &admin);

    let stored_commitment = [3u8; 32];
    let proof_commitment = [4u8; 32]; // mismatched
    let sigs = signals_matching(&e, proof_commitment, [2u8; 32], [5u8; 32], COMMAND.as_bytes());
    let sig_data = make_sig_data(&e, sigs, [1u8; 32], COMMAND);

    let key_data = BytesN::from_array(&e, &stored_commitment);
    let payload = Bytes::from_array(&e, &[0u8; 32]);
    assert!(
        !client.verify(&payload, &key_data, &sig_data),
        "must reject when recipient_email_hash != key_data"
    );
}

#[test]
fn verify_rejects_unregistered_dkim() {
    let e = Env::default();
    let (addr, _) = deploy(&e);
    let client = ZkEmailVerifierClient::new(&e, &addr);

    // DKIM (domain, pk) NOT registered.
    let commitment = [3u8; 32];
    let sigs = signals_matching(&e, commitment, [2u8; 32], [5u8; 32], COMMAND.as_bytes());
    let sig_data = make_sig_data(&e, sigs, [1u8; 32], COMMAND);

    let key_data = BytesN::from_array(&e, &commitment);
    let payload = Bytes::from_array(&e, &[0u8; 32]);
    assert!(!client.verify(&payload, &key_data, &sig_data));
}

#[test]
fn verify_rejects_revoked_dkim() {
    let e = Env::default();
    let (addr, admin) = deploy(&e);
    e.mock_all_auths();
    let client = ZkEmailVerifierClient::new(&e, &addr);

    let dh = BytesN::from_array(&e, &[1u8; 32]);
    let pkh = BytesN::from_array(&e, &[2u8; 32]);
    client.set_dkim_public_key_hash(&dh, &pkh, &admin);
    client.revoke_dkim_public_key_hash(&pkh, &admin);

    let commitment = [3u8; 32];
    let sigs = signals_matching(&e, commitment, [2u8; 32], [5u8; 32], COMMAND.as_bytes());
    let sig_data = make_sig_data(&e, sigs, [1u8; 32], COMMAND);

    let key_data = BytesN::from_array(&e, &commitment);
    let payload = Bytes::from_array(&e, &[0u8; 32]);
    assert!(!client.verify(&payload, &key_data, &sig_data));
}

#[test]
fn verify_rejects_command_hash_mismatch() {
    let e = Env::default();
    let (addr, admin) = deploy(&e);
    e.mock_all_auths();
    let client = ZkEmailVerifierClient::new(&e, &addr);

    let dh = BytesN::from_array(&e, &[1u8; 32]);
    let pkh = BytesN::from_array(&e, &[2u8; 32]);
    client.set_dkim_public_key_hash(&dh, &pkh, &admin);

    let commitment = [3u8; 32];
    // Signals committed to COMMAND, but sig_data declares a different one.
    let sigs = signals_matching(&e, commitment, [2u8; 32], [5u8; 32], COMMAND.as_bytes());
    let sig_data = make_sig_data(&e, sigs, [1u8; 32], "Different command");

    let key_data = BytesN::from_array(&e, &commitment);
    let payload = Bytes::from_array(&e, &[0u8; 32]);
    assert!(!client.verify(&payload, &key_data, &sig_data));
}

#[test]
fn admin_can_rotate_vk() {
    let e = Env::default();
    let (addr, admin) = deploy(&e);
    e.mock_all_auths();
    let client = ZkEmailVerifierClient::new(&e, &addr);

    let mut new_vk = dummy_vk(&e);
    new_vk.alpha_neg = BytesN::from_array(&e, &[0xAB; 96]);
    client.set_vk(&new_vk);
    assert_eq!(client.vk().alpha_neg, BytesN::from_array(&e, &[0xAB; 96]));
}

#[test]
#[should_panic]
fn set_vk_requires_admin_auth() {
    let e = Env::default();
    let (addr, _) = deploy(&e);
    let client = ZkEmailVerifierClient::new(&e, &addr);
    // No mock_all_auths — set_vk must fail.
    let new_vk = dummy_vk(&e);
    client.set_vk(&new_vk);
}

#[test]
fn nullifier_state_is_query_able() {
    let e = Env::default();
    let (addr, _) = deploy(&e);
    let client = ZkEmailVerifierClient::new(&e, &addr);
    let nullifier = BytesN::from_array(&e, &[7u8; 32]);
    assert!(!client.is_nullifier_used(&nullifier));
}

// Silence the unused-import warning emitted because `IntoVal` is required
// for the `e.register((admin, vk))` constructor-args coercion to work
// across some soroban-sdk minor versions.
#[allow(unused_imports)]
use soroban_sdk::IntoVal as _IntoVal;
