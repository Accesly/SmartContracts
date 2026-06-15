//! End-to-end Smart Account construction test (v2-legacy).
//!
//! Construye un `AcceslySmartAccount` contra los verifiers y policies reales
//! que NO están deprecados. Para `zk_email_verifier` se pasa una `Address::generate()`
//! dummy porque el contrato ZK email quedó fuera de scope (2026-06-15) — el
//! Smart Account v2-legacy aún tiene `zk_email_verifier` como argumento del
//! constructor por compatibilidad, pero el flujo de recovery ya no usa esa rule
//! (Recovery v2 OTP-email lo reemplaza, ver SDKAccesly/docs/Plan_Final_v1.md).
//!
//! Tests removidos en Fase 0:
//!  - `setup_yield_installs_yield_auto_rule` — yield interno fuera de scope.
//!  - `setup_yield_cannot_be_called_twice` — idem.
//!
//! La función `setup_yield()` sigue existiendo en v2-legacy pero ya no se
//! ejercita en CI. SmartAccount v3 (Fase 1) la elimina por completo.

use accesly_ed25519_verifier::Ed25519Verifier;
use accesly_secp256r1_verifier::Secp256r1Verifier;
use accesly_smart_account::{AcceslySmartAccount, AcceslySmartAccountClient, StellarAsset};
use accesly_spending_limit::SpendingLimitPolicy;
use accesly_zk_email_verifier::{VerifyingKey, ZkEmailVerifier, NUM_PUBLIC_SIGNALS};

use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, IntoVal, Val, Vec};
use stellar_accounts::policies::spending_limit::SpendingLimitAccountParams;

const DAY_IN_LEDGERS: u32 = 17_280;

struct Dependencies {
    ed25519_verifier: Address,
    secp256r1_verifier: Address,
    /// Sigue siendo una instancia real porque el SmartAccount v2-legacy llama
    /// `batch_canonicalize_key` durante `__constructor`. SmartAccount v3 (Fase 1)
    /// elimina la dep y este campo desaparece.
    zk_email_verifier: Address,
    spending_limit_policy: Address,
    usdc_sac: Address,
    eurc_sac: Address,
}

fn dummy_vk(e: &Env) -> VerifyingKey {
    let mut ic = soroban_sdk::Vec::new(e);
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

fn deploy_dependencies(e: &Env) -> Dependencies {
    let zk_admin = Address::generate(e);
    let zk_vk = dummy_vk(e);

    Dependencies {
        ed25519_verifier: e.register(Ed25519Verifier, ()),
        secp256r1_verifier: e.register(Secp256r1Verifier, ()),
        zk_email_verifier: e.register(ZkEmailVerifier, (zk_admin, zk_vk)),
        spending_limit_policy: e.register(SpendingLimitPolicy, ()),
        usdc_sac: Address::generate(e),
        eurc_sac: Address::generate(e),
    }
}

fn build_spending_params() -> SpendingLimitAccountParams {
    SpendingLimitAccountParams {
        spending_limit: 500_000_000,
        period_ledgers: DAY_IN_LEDGERS,
    }
}

fn deploy_smart_account(e: &Env, d: &Dependencies, tx_targets: Vec<Address>) -> Address {
    let owner_ed25519 = BytesN::from_array(e, &[1u8; 32]);
    let email_commitment = BytesN::from_array(e, &[2u8; 32]);
    let secp256r1_pubkey = BytesN::from_array(e, &[3u8; 65]);
    let trusted_assets: Vec<StellarAsset> = Vec::new(e);

    let spending_val: Val = build_spending_params().into_val(e);

    e.register(
        AcceslySmartAccount,
        (
            owner_ed25519,
            email_commitment,
            secp256r1_pubkey,
            d.ed25519_verifier.clone(),
            d.secp256r1_verifier.clone(),
            d.spending_limit_policy.clone(),
            spending_val,
            tx_targets,
            d.zk_email_verifier.clone(),
            trusted_assets,
        ),
    )
}

#[test]
fn smart_account_constructor_wires_real_contracts_with_two_tokens() {
    let e = Env::default();
    e.mock_all_auths();

    let d = deploy_dependencies(&e);
    let mut tx_targets = Vec::new(&e);
    tx_targets.push_back(d.usdc_sac.clone());
    tx_targets.push_back(d.eurc_sac.clone());

    let sa = deploy_smart_account(&e, &d, tx_targets);

    let client = AcceslySmartAccountClient::new(&e, &sa);

    // v2-legacy: 2 biometric-tx (one per tx_target) + admin-cfg + zk-recovery + sep10-auth = 5.
    // En SmartAccount v3 (Fase 1) sería 2 + admin-cfg + sep10-auth = 4 (sin zk-recovery).
    assert_eq!(
        client.get_context_rules_count(),
        5,
        "v2-legacy: 2 biometric-tx + 3 base rules (admin-cfg, zk-recovery, sep10-auth)"
    );
}

#[test]
fn smart_account_constructor_with_empty_tx_targets_installs_only_base_rules() {
    let e = Env::default();
    e.mock_all_auths();

    let d = deploy_dependencies(&e);
    let tx_targets: Vec<Address> = Vec::new(&e);

    let sa = deploy_smart_account(&e, &d, tx_targets);

    let client = AcceslySmartAccountClient::new(&e, &sa);

    // 0 biometric-tx + admin-cfg + zk-recovery + sep10-auth = 3.
    // El SDK puede instalar biometric-tx rules dinámicamente vía admin-cfg.
    assert_eq!(
        client.get_context_rules_count(),
        3,
        "expected only the 3 base rules when tx_targets is empty"
    );
}

#[test]
fn rule_zero_is_biometric_tx_scoped_to_first_tx_target() {
    let e = Env::default();
    e.mock_all_auths();

    let d = deploy_dependencies(&e);
    let mut tx_targets = Vec::new(&e);
    tx_targets.push_back(d.usdc_sac.clone());

    let sa = deploy_smart_account(&e, &d, tx_targets);

    let client = AcceslySmartAccountClient::new(&e, &sa);
    let rule = client.get_context_rule(&0);

    assert_eq!(
        rule.name,
        soroban_sdk::String::from_str(&e, "biometric-tx"),
        "rule 0 must be biometric-tx"
    );
    assert_eq!(
        rule.signers.len(),
        1,
        "biometric-tx has exactly one signer (owner ed25519)"
    );
    assert_eq!(
        rule.policies.len(),
        1,
        "biometric-tx has exactly one policy (spending-limit)"
    );
}

#[test]
#[should_panic]
fn smart_account_constructor_cannot_be_called_twice() {
    let e = Env::default();
    e.mock_all_auths();

    let d = deploy_dependencies(&e);
    let mut tx_targets = Vec::new(&e);
    tx_targets.push_back(d.usdc_sac.clone());

    let sa = deploy_smart_account(&e, &d, tx_targets.clone());

    // Second call must panic with AlreadyInitialized (9001).
    let owner_ed25519 = BytesN::from_array(&e, &[9u8; 32]);
    let email_commitment = BytesN::from_array(&e, &[9u8; 32]);
    let secp256r1_pubkey = BytesN::from_array(&e, &[9u8; 65]);

    let spending_val: Val = build_spending_params().into_val(&e);

    e.as_contract(&sa, || {
        AcceslySmartAccount::__constructor(
            &e,
            owner_ed25519,
            email_commitment,
            secp256r1_pubkey,
            d.ed25519_verifier.clone(),
            d.secp256r1_verifier.clone(),
            d.spending_limit_policy.clone(),
            spending_val,
            tx_targets,
            d.zk_email_verifier.clone(),
            Vec::new(&e),
        );
    });
}
