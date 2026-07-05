//! # Accesly Smart Account v3
//!
//! Reescritura del Smart Account post nuevo spec (2026-06-15). Cambios clave
//! vs v2-legacy (`accesly-smart-account`):
//!
//! 1. **Constructor minimal** — sale `zk_email_verifier`, sale `trusted_assets`.
//!    El backend `create-wallet` arma `change_trust` ops por fuera.
//! 2. **Sin `setup_yield`** — yield interno fuera de scope. Etherfuse cubre
//!    rendimiento off-chain.
//! 3. **Sin context rule `zk-recovery`** — el recovery v2 (OTP-email + password
//!    de Cognito) reconstruye la seed en cliente y firma una tx normal vía
//!    `admin-cfg`. No requiere verifier ZK on-chain.
//! 4. **Función pública `rotate_signer`** — pieza clave del recovery v2.
//!    Rota owner_ed25519, secp256r1 pubkey y email_commitment en una sola tx
//!    atómica firmada con la seed reconstruida (admin-cfg auth).
//! 5. **Deploy en 2 fases (Fase R, 2026-06-25)**: tras protocol 27 bajar el
//!    cap de `txWriteBytes` a 132KB, el constructor que invocaba
//!    `setup_context_rules` (lo que toca las WASMs de los verifiers via
//!    `batch_canonicalize_key`) excedía el cap (~163KB). Se separó la lógica:
//!      - `__constructor(deployer)`: solo guarda el deployer autorizado (~95KB tx).
//!      - `bootstrap(...)`: instala las rules y persiste storage (~30KB tx,
//!        verifiers van como readOnly porque ya están deployados).
//! 6. **v3.2.0 (Fase T, 2026-07-03)**: `rotate_signer` particionado. En wallets
//!    con 4+ context rules el rotate atómico también excedía el cap P27
//!    (medido: 166KB write en wallet con admin-cfg + sep10-auth + 2 biometric-tx,
//!    ver `Testnet_Deployment.md`). Se agregan:
//!      - `rotate_signer_partial(rule_ids, new_owner, new_secp)`: rota solo
//!        el subset de rules pasadas. Sin `email_commitment`, sin evento —
//!        pensado para llamarse N veces batcheando.
//!      - `finalize_rotation(new_owner, new_secp, new_email_commitment)`:
//!        actualiza el email_commitment y emite `SignerRotated`. Se llama
//!        una vez tras cubrir todas las rules con `rotate_signer_partial`.
//!    El `rotate_signer` atómico se mantiene por retro-compat para wallets
//!    con <= 3 rules donde sigue cabiendo bajo el cap.
//!
//! Ver SDKAccesly/docs/Plan_Final_v1.md §11 para el spec completo.
//!
//! ## Context Rules instaladas en `bootstrap()`
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
    /// `bootstrap` requiere auth del deployer que se registró en el constructor.
    NotAuthorizedDeployer = 9002,
    /// Operación sobre un SA que aún no llamó a `bootstrap()`.
    NotYetBootstrapped = 9003,
    /// `rotate_signer` no encontró un signer existente que reemplazar.
    SignerNotFoundForRotation = 9101,
    /// `rotate_signer_partial` recibió `rule_ids` vacío. El caller debe pasar
    /// al menos un rule para rotar; si no hay nada que rotar, no llamar.
    EmptyRuleIdsInPartial = 9102,
    /// `rotate_signer_partial` recibió un rule_id que no existe en la wallet.
    RuleIdOutOfRange = 9103,
    /// `rotate_signer_partial` intentó tocar una regla que no es biometric-tx,
    /// admin-cfg ni sep10-auth. Esas se rotan aparte con `add_signer/remove_signer`
    /// firmado por admin-cfg — no las mueve el flow de recovery.
    RuleNotRotatable = 9104,
}

#[contracttype]
enum StorageKey {
    /// Marca que `bootstrap()` ya corrió. Antes de eso el SA tiene contract
    /// instance pero ninguna rule — todas las operaciones del usuario fallan.
    Initialized,
    /// Address que firmó el `createContract`. Es el único que puede llamar a
    /// `bootstrap()`. Para Accesly esto es siempre `channels-fund` del backend.
    /// Esta storage entry se borra al final de `bootstrap()` (one-shot use).
    Deployer,
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
    /// Crea el Smart Account v3 con storage mínimo. Solo guarda el `deployer`
    /// autorizado para llamar a `bootstrap()`.
    ///
    /// Esta separación deploy/bootstrap es por el cap de `txWriteBytes` de
    /// Soroban protocol 27 (132KB). Un constructor que invocara
    /// `setup_context_rules` tocaría las WASMs de los 2 verifiers (~47KB) +
    /// la WASM del SA (~91KB) + storage = ~163KB, sobre el cap. Splitea:
    ///   - Deploy (`__constructor`): SA WASM + 1 storage entry → ~95KB ✓
    ///   - Bootstrap: verifiers como readOnly + rules/signers data → ~30KB ✓
    ///
    /// # Arguments
    /// * `deployer` — Address que firmó el `createContract`. Es el único que
    ///   puede llamar `bootstrap()` para completar la inicialización. En el
    ///   backend de Accesly esto es siempre `channels-fund`.
    pub fn __constructor(e: &Env, deployer: Address) {
        e.storage().instance().set(&StorageKey::Deployer, &deployer);
    }

    /// Completa la inicialización del Smart Account: persiste signers + verifiers
    /// en storage e instala las 3 context rules base (biometric-tx × N + admin-cfg
    /// + sep10-auth).
    ///
    /// Solo puede llamarse UNA VEZ y solo por el `deployer` registrado en
    /// `__constructor`. Tras el éxito, el storage de `Deployer` se borra y el
    /// flag `Initialized` se setea — futuras llamadas a `bootstrap` panican.
    ///
    /// # Arguments
    /// * `owner_ed25519`         — Pubkey ed25519 reconstruida F1+F2+F3 (32 bytes).
    /// * `email_commitment`      — `sha256(email || salt)` (32 bytes).
    /// * `secp256r1_pubkey`      — Pubkey del passkey (65 bytes uncompressed).
    /// * `ed25519_verifier`      — Address del Ed25519Verifier compartido.
    /// * `secp256r1_verifier`    — Address del Secp256r1Verifier compartido.
    /// * `spending_limit_policy` — Address del SpendingLimitPolicy compartido.
    /// * `spending_limit_params` — XDR `SpendingLimitAccountParams`.
    /// * `tx_targets`            — Vec de SAC addresses para spending-limit.
    ///   Vacío → solo 2 rules base (admin-cfg + sep10-auth); el backend
    ///   agrega biometric-tx después vía `activate-asset`.
    pub fn bootstrap(
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
        // 1. Idempotencia: bootstrap es one-shot.
        if e.storage().instance().has(&StorageKey::Initialized) {
            panic_with_error!(e, SmartAccountV3Error::AlreadyInitialized);
        }

        // 2. Auth: solo el deployer registrado en __constructor puede ejecutar
        // bootstrap. Esto previene griefing donde un tercero llame bootstrap
        // con sus propias keys antes que el backend legítimo.
        let deployer: Address = e
            .storage()
            .instance()
            .get(&StorageKey::Deployer)
            .unwrap_or_else(|| panic_with_error!(e, SmartAccountV3Error::NotAuthorizedDeployer));
        deployer.require_auth();

        // 3. Persistir email_commitment + verifiers (sigue siendo lo mismo que
        // hacía el constructor viejo). rotate_signer los necesita después.
        e.storage().instance().set(&StorageKey::Initialized, &true);
        e.storage()
            .instance()
            .set(&StorageKey::EmailCommitment, &email_commitment);
        e.storage()
            .instance()
            .set(&StorageKey::Ed25519Verifier, &ed25519_verifier);
        e.storage()
            .instance()
            .set(&StorageKey::Secp256r1Verifier, &secp256r1_verifier);

        // 4. Borrar el Deployer storage — ya no se necesita y libera espacio.
        e.storage().instance().remove(&StorageKey::Deployer);

        // 5. Instalar las context rules base.
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

    /// Devuelve `true` si `bootstrap()` ya fue llamado y el SA está operativo.
    pub fn is_initialized(e: &Env) -> bool {
        e.storage().instance().has(&StorageKey::Initialized)
    }

    /// Devuelve el `email_commitment` actual (útil para auditoría off-chain).
    /// Devuelve zeros si el SA aún no se bootstrappeó.
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

    /// Rota el signer de un subconjunto de rules — pieza 1 del flow de recovery
    /// particionado (v3.2.0, Fase T).
    ///
    /// Diseñada para wallets con 4+ context rules donde el `rotate_signer`
    /// atómico excede el cap P27 de `txWriteBytes` (132KB). El caller (SDK)
    /// enumera las rules on-chain, agrupa por batches que caben bajo el cap
    /// (~2-3 rules por batch en la práctica), y llama esta función N veces.
    /// Termina con `finalize_rotation` para persistir `email_commitment` y
    /// emitir `SignerRotated`.
    ///
    /// # Estado intermedio
    /// Durante la ventana entre el primer `rotate_signer_partial` y el
    /// `finalize_rotation`, algunas rules apuntan al signer viejo y otras al
    /// nuevo. Ambos pueden firmar mientras dure ese estado — es responsabilidad
    /// del SDK completar el flow en el mismo commit lógico. Si el SDK falla
    /// entre calls, retry hasta cerrar la rotación con `finalize_rotation`.
    ///
    /// # Auth
    /// Requiere admin-cfg. La primera call se autoriza con el signer viejo;
    /// las siguientes también, mientras `admin-cfg` aún tenga el viejo. Si el
    /// caller decidió incluir `admin-cfg` en el primer batch, las siguientes
    /// calls deben autorizarse con el NUEVO signer.
    pub fn rotate_signer_partial(
        e: &Env,
        rule_ids: Vec<u32>,
        new_owner_ed25519: BytesN<32>,
        new_secp256r1_pubkey: BytesN<65>,
    ) {
        e.current_contract_address().require_auth();

        if rule_ids.is_empty() {
            panic_with_error!(e, SmartAccountV3Error::EmptyRuleIdsInPartial);
        }

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

        let count = smart_account_lib::get_context_rules_count(e);
        let biometric_tx_name = String::from_str(e, "biometric-tx");
        let admin_cfg_name = String::from_str(e, "admin-cfg");
        let sep10_name = String::from_str(e, "sep10-auth");

        for i in 0..rule_ids.len() {
            let rule_id = rule_ids.get(i).unwrap();

            if rule_id >= count {
                panic_with_error!(e, SmartAccountV3Error::RuleIdOutOfRange);
            }

            let rule = smart_account_lib::get_context_rule(e, rule_id);

            // Solo procesamos rules que sabemos rotar. Session-key, allowlist,
            // upgrade-rule, etc. requieren un flow distinto (el caller las
            // gestiona con admin-cfg add/remove_signer aparte).
            let rotatable = rule.name == biometric_tx_name
                || rule.name == admin_cfg_name
                || rule.name == sep10_name;
            if !rotatable {
                panic_with_error!(e, SmartAccountV3Error::RuleNotRotatable);
            }

            // El esquema del bootstrap solo deja 1 signer por rule. Si el SDK
            // agregó signers adicionales fuera del path canónico, no los
            // tocamos aquí — el caller debe usar `add_signer/remove_signer`.
            if rule.signer_ids.len() != 1 {
                continue;
            }
            let old_signer_id = rule.signer_ids.get(0).unwrap();

            if rule.name == biometric_tx_name || rule.name == admin_cfg_name {
                smart_account_lib::add_signer(e, rule_id, &new_owner_signer);
                smart_account_lib::remove_signer(e, rule_id, old_signer_id);
            } else {
                // sep10-auth
                smart_account_lib::add_signer(e, rule_id, &new_secp_signer);
                smart_account_lib::remove_signer(e, rule_id, old_signer_id);
            }
        }
    }

    /// Cierra un flow de rotate particionado — pieza 2 (final) de v3.2.0.
    ///
    /// Persiste `email_commitment` en storage y emite `SignerRotated` con el
    /// set completo de nuevos identificadores. NO toca ningún rule; asume que
    /// las calls previas a `rotate_signer_partial` ya cubrieron todas las
    /// rules que tenían el signer viejo.
    ///
    /// # Auth
    /// Requiere admin-cfg firmado por el **nuevo** owner ed25519 (las calls
    /// previas ya migraron al menos la rule admin-cfg). Este check funciona
    /// como safety net contra un caller que llame `finalize_rotation` sin
    /// haber ejecutado el batch completo.
    pub fn finalize_rotation(
        e: &Env,
        new_owner_ed25519: BytesN<32>,
        new_secp256r1_pubkey: BytesN<65>,
        new_email_commitment: BytesN<32>,
    ) {
        e.current_contract_address().require_auth();

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
