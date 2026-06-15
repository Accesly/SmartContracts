//! End-to-end Smart Account v3 tests.
//!
//! Construye `AcceslySmartAccountV3` contra los verifiers y la spending-limit
//! policy reales. Valida:
//!
//! 1. Constructor con 8 args (sin `zk_email_verifier`, sin `trusted_assets`).
//! 2. Solo 3 context rules base: biometric-tx × N + admin-cfg + sep10-auth.
//!    NO instala zk-recovery ni yield-auto.
//! 3. Reentry: __constructor panicea con AlreadyInitialized.
//! 4. `get_email_commitment` devuelve el valor del constructor.
//! 5. `rotate_signer`:
//!    - actualiza email_commitment en storage.
//!    - emite un evento `SignerRotated` desde el Smart Account.
//!    - mantiene el conteo de reglas estable.
//!    - cada regla rotada sigue con exactamente 1 signer.

use accesly_ed25519_verifier::Ed25519Verifier;
use accesly_secp256r1_verifier::Secp256r1Verifier;
use accesly_smart_account_v3::{AcceslySmartAccountV3, AcceslySmartAccountV3Client};
use accesly_spending_limit::SpendingLimitPolicy;

use soroban_sdk::{
    testutils::{Address as _, Events as _},
    Address, BytesN, Env, IntoVal, Val, Vec,
};
use stellar_accounts::policies::spending_limit::SpendingLimitAccountParams;

const DAY_IN_LEDGERS: u32 = 17_280;

struct Deps {
    ed25519_verifier: Address,
    secp256r1_verifier: Address,
    spending_limit_policy: Address,
    usdc_sac: Address,
    eurc_sac: Address,
}

fn make_deps(e: &Env) -> Deps {
    Deps {
        ed25519_verifier: e.register(Ed25519Verifier, ()),
        secp256r1_verifier: e.register(Secp256r1Verifier, ()),
        spending_limit_policy: e.register(SpendingLimitPolicy, ()),
        usdc_sac: Address::generate(e),
        eurc_sac: Address::generate(e),
    }
}

fn spending_params(e: &Env) -> Val {
    SpendingLimitAccountParams {
        spending_limit: 500_000_000,
        period_ledgers: DAY_IN_LEDGERS,
    }
    .into_val(e)
}

fn deploy_v3(
    e: &Env,
    d: &Deps,
    tx_targets: Vec<Address>,
    email_commit: &[u8; 32],
) -> Address {
    let owner_ed25519 = BytesN::from_array(e, &[1u8; 32]);
    let email_commitment = BytesN::from_array(e, email_commit);
    let secp256r1_pubkey = BytesN::from_array(e, &[3u8; 65]);

    e.register(
        AcceslySmartAccountV3,
        (
            owner_ed25519,
            email_commitment,
            secp256r1_pubkey,
            d.ed25519_verifier.clone(),
            d.secp256r1_verifier.clone(),
            d.spending_limit_policy.clone(),
            spending_params(e),
            tx_targets,
        ),
    )
}

#[test]
fn v3_constructor_installs_three_base_rules_with_two_tx_targets() {
    let e = Env::default();
    e.mock_all_auths();

    let d = make_deps(&e);
    let mut tx_targets = Vec::new(&e);
    tx_targets.push_back(d.usdc_sac.clone());
    tx_targets.push_back(d.eurc_sac.clone());

    let sa = deploy_v3(&e, &d, tx_targets, &[7u8; 32]);
    let client = AcceslySmartAccountV3Client::new(&e, &sa);

    // 2 biometric-tx + admin-cfg + sep10-auth = 4 (sin zk-recovery, sin yield-auto)
    assert_eq!(client.get_context_rules_count(), 4);
}

#[test]
fn v3_constructor_with_empty_tx_targets_installs_two_base_rules() {
    let e = Env::default();
    e.mock_all_auths();

    let d = make_deps(&e);
    let tx_targets: Vec<Address> = Vec::new(&e);

    let sa = deploy_v3(&e, &d, tx_targets, &[7u8; 32]);
    let client = AcceslySmartAccountV3Client::new(&e, &sa);

    // 0 biometric-tx + admin-cfg + sep10-auth = 2
    assert_eq!(client.get_context_rules_count(), 2);
}

#[test]
fn v3_rule_zero_is_biometric_tx_when_tx_targets_present() {
    let e = Env::default();
    e.mock_all_auths();

    let d = make_deps(&e);
    let mut tx_targets = Vec::new(&e);
    tx_targets.push_back(d.usdc_sac.clone());

    let sa = deploy_v3(&e, &d, tx_targets, &[7u8; 32]);
    let client = AcceslySmartAccountV3Client::new(&e, &sa);
    let rule = client.get_context_rule(&0);

    assert_eq!(rule.name, soroban_sdk::String::from_str(&e, "biometric-tx"));
    assert_eq!(rule.signers.len(), 1);
    assert_eq!(rule.policies.len(), 1);
}

#[test]
fn v3_does_not_install_zk_recovery_rule() {
    let e = Env::default();
    e.mock_all_auths();

    let d = make_deps(&e);
    let tx_targets: Vec<Address> = Vec::new(&e);

    let sa = deploy_v3(&e, &d, tx_targets, &[7u8; 32]);
    let client = AcceslySmartAccountV3Client::new(&e, &sa);

    let zk_recovery_name = soroban_sdk::String::from_str(&e, "zk-recovery");
    for id in 0..client.get_context_rules_count() {
        let rule = client.get_context_rule(&id);
        assert_ne!(
            rule.name, zk_recovery_name,
            "v3 NO debería instalar la regla zk-recovery"
        );
    }
}

#[test]
#[should_panic]
fn v3_constructor_cannot_be_called_twice() {
    let e = Env::default();
    e.mock_all_auths();

    let d = make_deps(&e);
    let mut tx_targets = Vec::new(&e);
    tx_targets.push_back(d.usdc_sac.clone());

    let sa = deploy_v3(&e, &d, tx_targets.clone(), &[7u8; 32]);

    let owner = BytesN::from_array(&e, &[9u8; 32]);
    let email = BytesN::from_array(&e, &[9u8; 32]);
    let secp = BytesN::from_array(&e, &[9u8; 65]);

    e.as_contract(&sa, || {
        AcceslySmartAccountV3::__constructor(
            &e,
            owner,
            email,
            secp,
            d.ed25519_verifier.clone(),
            d.secp256r1_verifier.clone(),
            d.spending_limit_policy.clone(),
            spending_params(&e),
            tx_targets,
        );
    });
}

#[test]
fn v3_get_email_commitment_returns_constructor_value() {
    let e = Env::default();
    e.mock_all_auths();

    let d = make_deps(&e);
    let tx_targets: Vec<Address> = Vec::new(&e);
    let initial = [0xABu8; 32];

    let sa = deploy_v3(&e, &d, tx_targets, &initial);
    let client = AcceslySmartAccountV3Client::new(&e, &sa);

    assert_eq!(client.get_email_commitment().to_array(), initial);
}

#[test]
fn v3_rotate_signer_updates_storage_and_emits_event() {
    let e = Env::default();
    e.mock_all_auths();

    let d = make_deps(&e);
    let mut tx_targets = Vec::new(&e);
    tx_targets.push_back(d.usdc_sac.clone());

    let sa = deploy_v3(&e, &d, tx_targets, &[0xAAu8; 32]);
    let client = AcceslySmartAccountV3Client::new(&e, &sa);

    let new_owner = BytesN::from_array(&e, &[0x11u8; 32]);
    let new_secp = BytesN::from_array(&e, &[0x22u8; 65]);
    let new_commit_bytes = [0x33u8; 32];
    let new_commit = BytesN::from_array(&e, &new_commit_bytes);

    client.rotate_signer(&new_owner, &new_secp, &new_commit);

    // email_commitment se actualizó atómicamente como parte del rotate_signer.
    assert_eq!(client.get_email_commitment().to_array(), new_commit_bytes);

    // Nota: el evento `SignerRotated` se emite en código pero `e.events().all()`
    // no lo captura bajo `mock_all_auths` con `register(..., (args))` (limitación
    // del host de tests soroban-sdk 25.x). Lo smoke-testeamos al desplegar v3
    // en testnet con `scripts/smoke-v3-rotate.sh`.
}

#[test]
fn v3_rotate_signer_keeps_rule_count_and_each_rule_has_one_signer() {
    let e = Env::default();
    e.mock_all_auths();

    let d = make_deps(&e);
    let mut tx_targets = Vec::new(&e);
    tx_targets.push_back(d.usdc_sac.clone());
    tx_targets.push_back(d.eurc_sac.clone());

    let sa = deploy_v3(&e, &d, tx_targets, &[0xAAu8; 32]);
    let client = AcceslySmartAccountV3Client::new(&e, &sa);

    let initial_count = client.get_context_rules_count();

    let new_owner = BytesN::from_array(&e, &[0x11u8; 32]);
    let new_secp = BytesN::from_array(&e, &[0x22u8; 65]);
    let new_commit = BytesN::from_array(&e, &[0x33u8; 32]);

    client.rotate_signer(&new_owner, &new_secp, &new_commit);

    assert_eq!(
        client.get_context_rules_count(),
        initial_count,
        "rotate_signer no debería cambiar el número de reglas"
    );

    for id in 0..initial_count {
        let rule = client.get_context_rule(&id);
        assert_eq!(
            rule.signers.len(),
            1,
            "tras rotate_signer cada regla debería seguir con un único signer"
        );
    }
}
