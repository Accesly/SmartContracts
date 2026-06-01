//! # Accesly — Smart Account
//!
//! Contrato principal. Un deploy por usuario, generado al registrarse con
//! su email (como Privy, pero en Stellar/Soroban).
//!
//! ## Arquitectura
//!
//! Cada Smart Account es una instancia de este contrato con:
//! - Un signer ed25519 principal (F1+F2+F3 reconstruido en el SDK).
//! - Context rules predefinidas (ver context_rules.rs).
//! - Verifiers compartidos (ed25519, secp256r1, zk-email) — deploy único en la red.
//! - Policies compartidas (spending_limit, session_key, yield_dist) — deploy único.
//!
//! ## Context Rules
//!
//! | IDs               | Nombre       | Cuándo se usa                                      |
//! |-------------------|--------------|----------------------------------------------------|
//! | 0 .. N-1          | biometric-tx | Transferencias normales (biométrico + spending limit). Una regla por token en `tx_targets` (`CallContract(target)`). |
//! | N                 | admin-cfg    | Cambiar signers/rules/upgrade (biométrico estricto) |
//! | N+1               | zk-recovery  | Recovery por ZK proof de email                     |
//! | N+2               | sep10-auth   | SEP-10 challenge (passkey secp256r1)                |
//! | N+3               | yield-auto   | Distribución automática yield CETES (sin firma)     |
//! | dinámica          | session-key  | Pagos pequeños con session key temporal             |
//! | dinámica          | allowlist-tx | Llamadas a contratos terceros permitidos            |
//!
//! Si `tx_targets` está vacío, no se instala ninguna regla `biometric-tx` en el
//! constructor — el SDK puede agregarlas después vía `admin-cfg`. `spending_limit_params`
//! se aplica con los mismos valores a cada regla `biometric-tx` instalada.
//!
//! ## Upgrade
//!
//! Los upgrades deben pasar por el TimelockController (48h delay).
//! El relayer propone, espera, y ejecuta. El upgrade requiere regla admin-cfg.
//!
//! ## Trustlines
//!
//! Al crear la cuenta se emite `TrustlinesRequired`. El relayer agrega las
//! operaciones `change_trust` en la misma transacción de deploy.
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    panic_with_error, Address, BytesN, Env, Map, String, Symbol, Val, Vec,
};
use stellar_accounts::smart_account::{
    self as smart_account_lib, AuthPayload, ContextRule, ContextRuleType, ExecutionEntryPoint,
    Signer, SmartAccount, SmartAccountError,
};
use stellar_contract_utils::upgradeable::{self as upgradeable_lib, Upgradeable};

use crate::context_rules::setup_context_rules;
use crate::trustlines::{emit_trustlines_required, StellarAsset};

// ── Errores y storage del contrato ───────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
enum SmartAccountContractError {
    AlreadyInitialized = 9001,
    /// `setup_yield` ya fue llamado para esta cuenta.
    YieldAlreadyInstalled = 9002,
}

#[contracttype]
enum SmartAccountStorageKey {
    Initialized,
    /// Marker de idempotencia para `setup_yield`.
    YieldInstalled,
}

// ── Contrato ──────────────────────────────────────────────────────────────────

#[contract]
pub struct AcceslySmartAccount;

#[contractimpl]
impl AcceslySmartAccount {
    /// Crea el Smart Account para un usuario.
    ///
    /// # Arguments
    /// * `owner_ed25519`          — Pubkey ed25519 del propietario (32 bytes).
    ///   Representa la llave reconstruida F1+F2+F3 en el flujo de onboarding.
    ///
    /// * `email_commitment`       — Hash del email del usuario (32 bytes).
    ///   Usado como key_data del signer zk-recovery. Identifica al propietario
    ///   para el recovery ZK sin revelar el email on-chain.
    ///
    /// * `secp256r1_pubkey`       — Pubkey del passkey/biométrico del dispositivo
    ///   (65 bytes, uncompressed). Usado en la regla sep10-auth.
    ///
    /// * `ed25519_verifier`       — Dirección del Ed25519Verifier compartido.
    /// * `secp256r1_verifier`     — Dirección del Secp256r1Verifier compartido.
    /// * `spending_limit_policy`  — Dirección del SpendingLimitPolicy compartido.
    /// * `spending_limit_params`  — Parámetros de instalación del spending limit
    ///   (XDR-encoded SpendingLimitAccountParams). Se reutilizan para cada entry de
    ///   `tx_targets` (mismo límite y ventana por token).
    /// * `tx_targets`             — Direcciones de los contratos de token (SAC) donde
    ///   el usuario quiere que aplique el spending limit. Por cada entry se crea una
    ///   regla `biometric-tx` con `CallContract(target)` + spending_limit. Si está vacía,
    ///   no se instala ninguna regla biometric-tx — el SDK debe agregarlas dinámicamente
    ///   vía `admin-cfg` (requerido por OZ v0.7.x, que rechaza spending-limit sobre reglas
    ///   `Default`).
    /// * `zk_email_verifier`      — Dirección del ZkEmailVerifier compartido.
    /// * `trusted_assets`          — Lista de assets para los que se crearán trustlines.
    ///   El SDK construye esta lista según la configuración del developer (puede ser vacía).
    ///   Los issuers reales (testnet/mainnet) los conoce el SDK, no el contrato.
    ///
    /// **Yield**: la configuración de `yield_policy` se difiere a `setup_yield()`
    /// post-deploy. Esto baja el footprint del constructor para caber dentro
    /// de los límites de Soroban protocol 26 (~25 write entries, ~130KB write
    /// bytes). El install del yield (con sus 7 config keys) ocurre en una
    /// segunda tx después del deploy.
    #[allow(clippy::too_many_arguments)]
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
        zk_email_verifier: Address,
        trusted_assets: Vec<StellarAsset>,
    ) {
        if e.storage()
            .instance()
            .has(&SmartAccountStorageKey::Initialized)
        {
            panic_with_error!(e, SmartAccountContractError::AlreadyInitialized);
        }
        e.storage()
            .instance()
            .set(&SmartAccountStorageKey::Initialized, &true);

        // Nota: email_commitment y secp256r1_pubkey se pasan a setup_context_rules
        // para que los signers tengan los key_data reales desde el primer momento.
        setup_context_rules(
            e,
            &owner_ed25519,
            &email_commitment,
            &secp256r1_pubkey,
            &ed25519_verifier,
            &secp256r1_verifier,
            &spending_limit_policy,
            spending_limit_params,
            &tx_targets,
            &zk_email_verifier,
        );

        // Emitir trustlines requeridas para que el relayer las incluya en la tx.
        // La lista viene del SDK según la configuración del developer.
        if !trusted_assets.is_empty() {
            emit_trustlines_required(e, trusted_assets);
        }
    }

    /// Instala la regla `yield-auto` + el `YieldDistributionPolicy` post-deploy.
    ///
    /// Esta función se difiere del constructor para que el deploy inicial
    /// caiga dentro de los límites de footprint de Soroban protocol 26. Una
    /// vez que el Smart Account está desplegado, el dueño (a través de la
    /// regla `admin-cfg`) llama esta función en una segunda transacción
    /// para activar la distribución automática de yield CETES.
    ///
    /// # Auth
    /// Requiere que el Smart Account autorice (via context rule `admin-cfg`
    /// con firma biométrica ed25519 del propietario).
    ///
    /// # Idempotencia
    /// Solo se puede llamar una vez. Reintentos panic con `YieldAlreadyInstalled`.
    /// Para desinstalar + reinstalar, usar `uninstall` del propio yield policy
    /// vía rule `admin-cfg` y luego volver a llamar `setup_yield`.
    pub fn setup_yield(
        e: &Env,
        yield_policy: Address,
        yield_params: Val,
        cetes_contract: Address,
    ) {
        // Auth del Smart Account (admin-cfg cubre con biométrico ed25519)
        e.current_contract_address().require_auth();

        if e.storage()
            .instance()
            .has(&SmartAccountStorageKey::YieldInstalled)
        {
            panic_with_error!(e, SmartAccountContractError::YieldAlreadyInstalled);
        }
        e.storage()
            .instance()
            .set(&SmartAccountStorageKey::YieldInstalled, &true);

        // Misma lógica que estaba antes en setup_context_rules para yield-auto:
        // signer vacío (relayer es quien firma), policy = yield_policy.
        let signers: soroban_sdk::Vec<Signer> = soroban_sdk::Vec::new(e);
        let mut policies: soroban_sdk::Map<Address, Val> = soroban_sdk::Map::new(e);
        policies.set(yield_policy, yield_params);

        smart_account_lib::add_context_rule(
            e,
            &stellar_accounts::smart_account::ContextRuleType::CallContract(cetes_contract),
            &soroban_sdk::String::from_str(e, "yield-auto"),
            None,
            &signers,
            &policies,
        );
    }
}

// ── CustomAccountInterface ────────────────────────────────────────────────────

#[contractimpl]
impl CustomAccountInterface for AcceslySmartAccount {
    type Error = SmartAccountError;
    type Signature = AuthPayload;

    /// Punto central de autorización. OZ maneja toda la lógica de:
    /// - Verificar firmas (ed25519, secp256r1, zk-email)
    /// - Evaluar context rules
    /// - Llamar enforce() en las policies (spending_limit, session_key, yield_dist)
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
impl SmartAccount for AcceslySmartAccount {}

// ── ExecutionEntryPoint (llamadas a contratos externos desde la cuenta) ────────

#[contractimpl(contracttrait)]
impl ExecutionEntryPoint for AcceslySmartAccount {}

// ── Upgradeable (protegido por Timelock 48h en la regla admin-cfg) ────────────

#[contractimpl]
impl Upgradeable for AcceslySmartAccount {
    /// Upgrade del contrato. Requiere:
    /// 1. Pasar por la regla "admin-cfg" (biométrico ed25519).
    /// 2. El TimelockController habrá validado las 48h antes de que este
    ///    endpoint sea accesible (el timelock owner propone + ejecuta).
    fn upgrade(e: &Env, new_wasm_hash: BytesN<32>, _operator: Address) {
        e.current_contract_address().require_auth();
        upgradeable_lib::upgrade(e, &new_wasm_hash);
    }
}
