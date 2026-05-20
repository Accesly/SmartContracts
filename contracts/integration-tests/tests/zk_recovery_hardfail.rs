//! ZK recovery hard-fail regression lock.
//!
//! `zk-email-verifier.verify()` is intentionally hard-coded to return `false`
//! until the groth16/plonk circuit verifier is integrated (see
//! `Pendientes_Fase2.md`). This is a security decision driven by the Almanax
//! scan finding from 2026-04-27: a DKIM-only check (without binding to
//! `key_data` or `signature_payload`) allows any attacker holding any
//! registered DKIM pair to bypass recovery auth.
//!
//! This test exists to prevent accidentally flipping `verify()` back to a
//! permissive value during Fase 2 work, without explicitly removing this
//! regression lock at the same time.

use accesly_zk_email_verifier::{ZkEmailProof, ZkEmailVerifier, ZkEmailVerifierClient};
use soroban_sdk::{
    testutils::Address as _,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env,
};

fn make_proof_xdr(e: &Env, domain_hash: [u8; 32], pk_hash: [u8; 32]) -> Bytes {
    let proof = ZkEmailProof {
        domain_hash: BytesN::from_array(e, &domain_hash),
        public_key_hash: BytesN::from_array(e, &pk_hash),
        proof: Bytes::from_array(e, &[0u8; 32]),
    };
    proof.to_xdr(e)
}

#[test]
fn verify_returns_false_even_for_registered_dkim_key() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    let verifier_addr = e.register(ZkEmailVerifier, (&admin,));
    let client = ZkEmailVerifierClient::new(&e, &verifier_addr);

    // Register a DKIM key — exactly the attacker's setup that the Almanax
    // finding described. Without the hard-fail, this would let any tx
    // authorized under zk-recovery succeed.
    let domain_hash = BytesN::from_array(&e, &[0xAAu8; 32]);
    let pk_hash = BytesN::from_array(&e, &[0xBBu8; 32]);
    client.set_dkim_public_key_hash(&domain_hash, &pk_hash, &admin);

    // Sanity: DKIM registry says the pair is valid.
    assert!(
        client.is_dkim_valid(&domain_hash, &pk_hash),
        "DKIM pair must be registered for this test to be meaningful"
    );

    // Now the verify() must STILL return false. This is the hard-fail.
    let signature_payload = Bytes::from_array(&e, &[0u8; 32]);
    let email_commitment = BytesN::from_array(&e, &[0xCCu8; 32]);
    let sig_data = make_proof_xdr(&e, [0xAAu8; 32], [0xBBu8; 32]);

    let result = client.verify(&signature_payload, &email_commitment, &sig_data);

    assert!(
        !result,
        "REGRESSION: zk-email verify() returned true. \
         The hard-fail in Pendientes_Fase2.md #1 was removed without integrating \
         the groth16/plonk circuit verifier. This re-opens the Almanax CRITICAL \
         finding (Apr 27 2026) that allows DKIM-only auth bypass."
    );
}

#[test]
fn verify_returns_false_for_unregistered_dkim_key_too() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    let verifier_addr = e.register(ZkEmailVerifier, (&admin,));
    let client = ZkEmailVerifierClient::new(&e, &verifier_addr);

    let signature_payload = Bytes::from_array(&e, &[0u8; 32]);
    let email_commitment = BytesN::from_array(&e, &[1u8; 32]);
    let sig_data = make_proof_xdr(&e, [0x11u8; 32], [0x22u8; 32]);

    assert!(
        !client.verify(&signature_payload, &email_commitment, &sig_data),
        "verify() must reject unregistered DKIM pairs (and any pair during Fase 1)"
    );
}
