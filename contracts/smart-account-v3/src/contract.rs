//! # Accesly Smart Account v3
//!
//! Reescritura del Smart Account post nuevo spec (2026-06-15). Cambios clave
//! vs v2-legacy (`accesly-smart-account`):
//!
//! 1. **Constructor 8 args** — sale `zk_email_verifier`, sale `trusted_assets`.
//!    El backend `create-wallet` arma `change_trust` ops por fuera.
//! 2. **Sin `setup_yield`** — yield interno fuera de scope. Etherfuse cubre
//!    rendimiento off-chain.
//! 3. **Sin context rule `zk-recovery`** — el recovery v2 (OTP-email + password
//!    de Cognito) reconstruye la seed en cliente y firma una tx normal vía
//!    `admin-cfg`. No requiere verifier ZK on-chain.
//! 4. **Nueva función pública `rotate_signer`** — pieza clave del recovery v2.
//!    Rota owner_ed25519, secp256r1 pubkey y email_commitment en una sola tx
//!    atómica firmada con la seed reconstruida (admin-cfg auth).
//!
//! Ver SDKAccesly/docs/Plan_Final_v1.md §11 para el spec completo.
//!
//! ## Context Rules instaladas en constructor
//!
//! | IDs       | Nombre        | ContextRuleType              | Signers              | Policies         |
//! |-----------|---------------|------------------------------|----------------------|------------------|
//! | 0 .. N-1  | biometric-tx  | CallContract(tx_target[i])   | ed25519 (External)   | spending_limit   |
//! | N         | admin-cfg     | Default                      | ed25519 (External)   | —                |
//! | N+1       | sep10-auth    | Default                      | secp256r1 (External) | —                |
//!
//! ## Upgrade
//!
//! Upgrades pasan por TimelockController (48h delay) y la regla admin-cfg.

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::Hash,
    panic_with_error, Address, Bytes, BytesN, Env, Map, String, Symbol, Val, Vec,
};
use stellar_accounts::smart_account::{
    self as smart_account_lib, AuthPayload, ContextRule, ContextRuleType, ExecutionEntryPoint,
    Signer, SmartAccount, SmartAccountError,
};
use stellar_contract_utils::upgradeable::{self as upgradeable_lib, Upgradeable};

use crate::context_rules::setup_context_rules;

// ── Errores y storage ────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
enum SmartAccountV3Error {
    AlreadyInitialized = 9001,
    /// `rotate_signer` no encontró un signer existente que reemplazar.
    SignerNotFoundForRotation = 9101,
}

#[contracttype]
enum StorageKey {
    Initialized,
    /// SHA-256(email || salt) — usado por el backend para discovery vía emailHash.
    /// Se actualiza en cada `rotate_signer`.
    EmailCommitment,
    /// Address del verifier ed25519 — necesario para reconstruir `Signer::External`
    /// dentro de `rotate_signer`.
    Ed25519Verifier,
    /// Address del verifier secp256r1 — idem para el signer del passkey.
    Secp256r1Verifier,
}

// ── Eventos ───────────────────────────────────────────────────────────────────

/// Emitido cuando `rotate_signer` rota exitosamente al nuevo set de signers.
/// El backend escucha este evento como audit trail del recovery completado.
#[contractevent]
#[derive(Clone)]
pub struct SignerRotated {
    #[topic]
    pub smart_account: Address,
    pub new_owner_ed25519: BytesN<32>,
    pub new_secp256r1_pubkey: BytesN<65>,
    pub new_email_commitment: BytesN<32>,
}

// ── Contrato ──────────────────────────────────────────────────────────────────

#[contract]
pub struct AcceslySmartAccountV3;

#[contractimpl]
impl AcceslySmartAccountV3 {
    /// Crea el Smart Account v3 para un usuario.
    ///
    /// # Arguments
    /// * `owner_ed25519`         — Pubkey ed25519 reconstruida F1+F2+F3 (32 bytes).
    /// * `email_commitment`      — `sha256(email || salt)` (32 bytes). Identifica
    ///   al propietario para discovery off-chain por parte del backend.
    /// * `secp256r1_pubkey`      — Pubkey del passkey (65 bytes uncompressed).
    /// * `ed25519_verifier`      — Address del Ed25519Verifier compartido.
    /// * `secp256r1_verifier`    — Address del Secp256r1Verifier compartido.
    /// * `spending_limit_policy` — Address del SpendingLimitPolicy compartido.
    /// * `spending_limit_params` — XDR `SpendingLimitAccountParams`. Mismo
    ///   límite + ventana para cada token en `tx_targets`.
    /// * `tx_targets`            — Vec de SAC addresses (USDC, EURC, MXNe…)
    ///   donde aplica el spending-limit. Vacío → solo 2 rules base; el SDK
    ///   agrega biometric-tx dinámicamente vía admin-cfg.
    pub fn __constructor(
        e: &Env,
        owner_ed25519: BytesN<32>,
        email_commitment: BytesN<32>,
        secp256r1_pubkey: BytesN<65>,
        ed25519_verifier: Address,
        secp256r1_verifier: Address,
        spending_limit_policy: Address,
        spending_limit_params: Val,
        tx_targets: Vec<Address>,
    ) {
        if e.storage().instance().has(&StorageKey::Initialized) {
            panic_with_error!(e, SmartAccountV3Error::AlreadyInitialized);
        }
        e.storage().instance().set(&StorageKey::Initialized, &true);

        // Persistimos email_commitment + verifiers para que rotate_signer pueda
        // reconstruir los Signer::External sin requerirlos como args.
        e.storage()
            .instance()
            .set(&StorageKey::EmailCommitment, &email_commitment);
        e.storage()
            .instance()
            .set(&StorageKey::Ed25519Verifier, &ed25519_verifier);
        e.storage()
            .instance()
            .set(&StorageKey::Secp256r1Verifier, &secp256r1_verifier);

        setup_context_rules(
            e,
            &owner_ed25519,
            &secp256r1_pubkey,
            &ed25519_verifier,
            &secp256r1_verifier,
            &spending_limit_policy,
            spending_limit_params,
            &tx_targets,
        );
    }

    /// Devuelve el `email_commitment` actual (útil para auditoría off-chain).
    pub fn get_email_commitment(e: &Env) -> BytesN<32> {
        e.storage()
            .instance()
            .get(&StorageKey::EmailCommitment)
            .unwrap_or_else(|| BytesN::from_array(e, &[0u8; 32]))
    }

    /// Rota los signers principales del Smart Account en una sola tx atómica.
    ///
    /// Pieza clave del flujo de recovery v2:
    ///   1. SDK reconstruye seed con F2+F3 (sin device).
    ///   2. SDK registra un new passkey + genera nuevo Shamir → F1', F2', F3'.
    ///   3. SDK firma esta tx con la seed VIEJA (sigue válida hasta rotate).
    ///   4. Soroban valida la firma contra `admin-cfg` rule.
    ///   5. Esta función rota:
    ///        - owner_ed25519 en todas las reglas biometric-tx + admin-cfg
    ///        - secp256r1_pubkey en sep10-auth
    ///        - email_commitment en storage
    ///   6. Emite `SignerRotated` event para audit trail del backend.
    ///
    /// # Auth
    /// Requiere que el Smart Account autorice (via context rule `admin-cfg`).
    pub fn rotate_signer(
        e: &Env,
        new_owner_ed25519: BytesN<32>,
        new_secp256r1_pubkey: BytesN<65>,
        new_email_commitment: BytesN<32>,
    ) {
        e.current_contract_address().require_auth();

        let ed25519_verifier: Address = e
            .storage()
            .instance()
            .get(&StorageKey::Ed25519Verifier)
            .unwrap_or_else(|| panic_with_error!(e, SmartAccountV3Error::SignerNotFoundForRotation));
        let secp256r1_verifier: Address = e
            .storage()
            .instance()
            .get(&StorageKey::Secp256r1Verifier)
            .unwrap_or_else(|| panic_with_error!(e, SmartAccountV3Error::SignerNotFoundForRotation));

        let new_owner_signer = Signer::External(
            ed25519_verifier,
            Bytes::from_slice(e, &new_owner_ed25519.to_array()),
        );
        let new_secp_signer = Signer::External(
            secp256r1_verifier,
            Bytes::from_slice(e, &new_secp256r1_pubkey.to_array()),
        );

        // Iteramos todas las context rules instaladas. Sabemos que el constructor
        // creó: N biometric-tx + admin-cfg + sep10-auth. Tras `add_context_rule`
        // dinámicas (session-key, etc.) el conteo crece, pero esas no contienen
        // el owner-signer así que las saltamos por nombre.
        let count = smart_account_lib::get_context_rules_count(e);
        let biometric_tx_name = String::from_str(e, "biometric-tx");
        let admin_cfg_name = String::from_str(e, "admin-cfg");
        let sep10_name = String::from_str(e, "sep10-auth");

        for rule_id in 0..count {
            let rule = smart_account_lib::get_context_rule(e, rule_id);

            // El esquema del constructor solo deja UN signer por regla. Si el
            // SDK agregó dinámicas adicionales, las saltamos.
            if rule.signer_ids.len() != 1 {
                continue;
            }
            let old_signer_id = rule.signer_ids.get(0).unwrap();

            if rule.name == biometric_tx_name || rule.name == admin_cfg_name {
                // Rotamos al nuevo ed25519 owner: add + remove (orden importa,
                // OZ rechaza eliminar el último signer de una regla).
                smart_account_lib::add_signer(e, rule_id, &new_owner_signer);
                smart_account_lib::remove_signer(e, rule_id, old_signer_id);
            } else if rule.name == sep10_name {
                smart_account_lib::add_signer(e, rule_id, &new_secp_signer);
                smart_account_lib::remove_signer(e, rule_id, old_signer_id);
            }
            // Cualquier otra regla (session-key, allowlist, upgrade-rule) se
            // queda intacta — el caller debería borrarlas aparte si quiere.
        }

        // Actualizamos email_commitment para audit y discovery off-chain.
        e.storage()
            .instance()
            .set(&StorageKey::EmailCommitment, &new_email_commitment);

        SignerRotated {
            smart_account: e.current_contract_address(),
            new_owner_ed25519,
            new_secp256r1_pubkey,
            new_email_commitment,
        }
        .publish(e);
    }
}

// ── CustomAccountInterface ────────────────────────────────────────────────────

#[contractimpl]
impl CustomAccountInterface for AcceslySmartAccountV3 {
    type Error = SmartAccountError;
    type Signature = AuthPayload;

    fn __check_auth(
        e: Env,
        signature_payload: Hash<32>,
        signatures: AuthPayload,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Self::Error> {
        smart_account_lib::do_check_auth(&e, &signature_payload, &signatures, &auth_contexts)
    }
}

// ── SmartAccount trait (gestión de reglas, signers, policies) ─────────────────

#[contractimpl(contracttrait)]
impl SmartAccount for AcceslySmartAccountV3 {}

// ── ExecutionEntryPoint ───────────────────────────────────────────────────────

#[contractimpl(contracttrait)]
impl ExecutionEntryPoint for AcceslySmartAccountV3 {}

// ── Upgradeable (protegido por Timelock 48h + admin-cfg) ──────────────────────

#[contractimpl]
impl Upgradeable for AcceslySmartAccountV3 {
    fn upgrade(e: &Env, new_wasm_hash: BytesN<32>, _operator: Address) {
        e.current_contract_address().require_auth();
        upgradeable_lib::upgrade(e, &new_wasm_hash);
    }
}
