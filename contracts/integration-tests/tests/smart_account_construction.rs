//! End-to-end Smart Account construction test.
//!
//! Wires every real verifier and policy contract used by the deploy script
//! and constructs an `AcceslySmartAccount` against them. Validates:
//!
//! 1. The constructor signature in `AcceslySmartAccount::__constructor`
//!    matches what `setup_context_rules` expects.
//! 2. The XDR-encoded `Val` params for spending-limit and yield-distribution
//!    deserialize correctly inside the policies.
//! 3. Cross-contract `PolicyClient::install()` calls succeed against the real
//!    `SpendingLimitPolicy` and `YieldDistributionPolicy` contracts.
//! 4. The right number of context rules is installed:
//!    `tx_targets.len()` biometric-tx rules + 3 base rules (admin-cfg,
//!    zk-recovery, sep10-auth). La regla `yield-auto` se difiere a
//!    `setup_yield()` post-deploy (protocol 26 footprint).
//!
//! If this test passes, `scripts/deploy_testnet.sh` + the Lambda `createWallet`
//! flow will succeed in deploying a per-user Smart Account.

use accesly_ed25519_verifier::Ed25519Verifier;
use accesly_secp256r1_verifier::Secp256r1Verifier;
use accesly_smart_account::{AcceslySmartAccount, AcceslySmartAccountClient, StellarAsset};
use accesly_spending_limit::SpendingLimitPolicy;
use accesly_yield_distribution::{YieldDistributionPolicy, YieldInstallParams, WEEK_IN_LEDGERS};
use accesly_zk_email_verifier::{VerifyingKey, ZkEmailVerifier, NUM_PUBLIC_SIGNALS};

use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, IntoVal, Val, Vec};
use stellar_accounts::policies::spending_limit::SpendingLimitAccountParams;

const DAY_IN_LEDGERS: u32 = 17_280;

struct Dependencies {
    ed25519_verifier: Address,
    secp256r1_verifier: Address,
    zk_email_verifier: Address,
    spending_limit_policy: Address,
    yield_policy: Address,
    cetes_contract: Address,
    accesly_wallet: Address,
    user_wallet: Address,
    relayer: Address,
    // Mock token SAC addresses that the SDK would pass as `tx_targets`.
    // In production these are USDC, EURC, MXNe, etc. — one biometric-tx
    // rule will be installed per entry.
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
        zk_email_verifier: e.register(ZkEmailVerifier, (zk_admin.clone(), zk_vk)),
        spending_limit_policy: e.register(SpendingLimitPolicy, ()),
        yield_policy: e.register(YieldDistributionPolicy, ()),
        cetes_contract: Address::generate(e),
        accesly_wallet: Address::generate(e),
        user_wallet: Address::generate(e),
        relayer: Address::generate(e),
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

fn build_yield_params(d: &Dependencies) -> YieldInstallParams {
    YieldInstallParams {
        cetes_contract: d.cetes_contract.clone(),
        accesly_wallet: d.accesly_wallet.clone(),
        user_wallet: d.user_wallet.clone(),
        relayer: d.relayer.clone(),
        period_ledgers: WEEK_IN_LEDGERS,
        accesly_bps: 5_000,
        max_amount_per_transfer: 1_000_000_000,
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
fn smart_account_constructor_wires_all_real_contracts_with_two_tokens() {
    let e = Env::default();
    e.mock_all_auths();

    let d = deploy_dependencies(&e);
    let mut tx_targets = Vec::new(&e);
    tx_targets.push_back(d.usdc_sac.clone());
    tx_targets.push_back(d.eurc_sac.clone());

    let sa = deploy_smart_account(&e, &d, tx_targets);

    let client = AcceslySmartAccountClient::new(&e, &sa);

    // 2 biometric-tx (one per tx_target) + admin-cfg + zk-recovery + sep10-auth = 5.
    // yield-auto se instala via setup_yield() post-deploy (no es parte del constructor).
    assert_eq!(
        client.get_context_rules_count(),
        5,
        "expected 2 biometric-tx + 3 base rules = 5 total"
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
    // yield-auto se difiere a setup_yield(). El SDK puede instalar biometric-tx
    // rules dinámicamente vía admin-cfg.
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
fn setup_yield_installs_yield_auto_rule() {
    let e = Env::default();
    e.mock_all_auths();

    let d = deploy_dependencies(&e);
    let mut tx_targets = Vec::new(&e);
    tx_targets.push_back(d.usdc_sac.clone());

    let sa = deploy_smart_account(&e, &d, tx_targets);
    let client = AcceslySmartAccountClient::new(&e, &sa);

    // Antes de setup_yield: 1 biometric-tx + 3 base = 4 rules.
    assert_eq!(client.get_context_rules_count(), 4);

    let yield_val: Val = build_yield_params(&d).into_val(&e);
    client.setup_yield(&d.yield_policy, &yield_val, &d.cetes_contract);

    // Después: yield-auto agregada como rule 4.
    assert_eq!(client.get_context_rules_count(), 5);
    let rule = client.get_context_rule(&4);
    assert_eq!(
        rule.name,
        soroban_sdk::String::from_str(&e, "yield-auto"),
        "rule 4 must be yield-auto"
    );
    assert_eq!(rule.signers.len(), 0, "yield-auto runs without user signature");
    assert_eq!(rule.policies.len(), 1, "yield-auto has yield-distribution policy");
}

#[test]
#[should_panic]
fn setup_yield_cannot_be_called_twice() {
    let e = Env::default();
    e.mock_all_auths();

    let d = deploy_dependencies(&e);
    let tx_targets: Vec<Address> = Vec::new(&e);
    let sa = deploy_smart_account(&e, &d, tx_targets);
    let client = AcceslySmartAccountClient::new(&e, &sa);

    let yield_val: Val = build_yield_params(&d).into_val(&e);
    client.setup_yield(&d.yield_policy, &yield_val, &d.cetes_contract);

    // Segundo call panicea con YieldAlreadyInstalled (9002).
    client.setup_yield(&d.yield_policy, &yield_val, &d.cetes_contract);
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
