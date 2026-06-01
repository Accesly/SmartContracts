//! # Context Rules predefinidas (Issues 1.4 y 1.9)
//!
//! Inicializa las context rules base en el constructor del Smart Account.
//!
//! ## Estructura
//!
//! | IDs               | Nombre        | ContextRuleType              | Signers              | Policies         |
//! |-------------------|---------------|------------------------------|----------------------|------------------|
//! | 0 .. N-1          | biometric-tx  | CallContract(tx_target[i])   | ed25519 (External)   | spending_limit   |
//! | N                 | admin-cfg     | Default                      | ed25519 (External)   | —                |
//! | N+1               | zk-recovery   | Default                      | zk_email (External)  | —                |
//! | N+2               | sep10-auth    | Default                      | secp256r1 (External) | —                |
//!
//! Donde `N = tx_targets.len()`. Si `tx_targets` está vacío, no se instala
//! ninguna regla `biometric-tx` en el constructor — el SDK puede agregarlas
//! después vía `admin-cfg`.
//!
//! **Yield**: la regla `yield-auto` (con su install de `YieldDistributionPolicy`)
//! se difiere a una llamada post-deploy de `AcceslySmartAccount::setup_yield()`
//! para que el footprint del constructor caiga dentro de los límites de
//! Soroban protocol 26. Antes vivía aquí como `N+3`; el install de la policy
//! escribe 7 config keys + TTL entries y empujaba el total fuera del cap.
//!
//! ## ¿Por qué una regla biometric-tx por token?
//!
//! La policy `SpendingLimit` de OZ stellar-accounts v0.7.x hard-rechaza
//! cualquier `ContextRule` cuyo `context_type` no sea `CallContract(_)` (error
//! `OnlyCallContractAllowed = 3227`). Como spending-limit es intrínsecamente
//! por-contrato, instalamos una regla por token bajo enforcement. `spending_limit_params`
//! se reutiliza para todas (mismo límite por token; si en el futuro se necesitan
//! límites distintos por token, cambiar el parámetro a `Map<Address, Val>`).
//!
//! ## Reglas dinámicas (añadidas por el SDK en runtime)
//!
//! - `session-key` (Default): External signer (session ed25519) + session_key_policy
//! - `allowlist-tx` (CallContract(target)): External signer (session key) sin policy
//! - `blend-rule` (Default): session key + blend_rule_policy (restrict pool + request types + max amount)
//! - `upgrade-rule` (Default): session key + upgrade_rule_policy (solo `upgrade` en target_contract)

use soroban_sdk::{Address, Bytes, BytesN, Env, Map, String, Val, Vec};
use stellar_accounts::smart_account::{self as smart_account_lib, ContextRuleType, Signer};

/// Instala las context rules base del Smart Account.
///
/// La regla `yield-auto` se difiere a `AcceslySmartAccount::setup_yield()` —
/// no se instala aquí. Ver `contract.rs` para el detalle.
#[allow(clippy::too_many_arguments)]
pub fn setup_context_rules(
    e: &Env,
    owner_ed25519: &BytesN<32>,
    email_commitment: &BytesN<32>,
    secp256r1_pubkey: &BytesN<65>,
    ed25519_verifier: &Address,
    secp256r1_verifier: &Address,
    spending_limit_policy: &Address,
    spending_limit_params: Val,
    tx_targets: &Vec<Address>,
    zk_email_verifier: &Address,
) {
    // ── Signers ───────────────────────────────────────────────────────────────

    // Signer ed25519 del propietario (biométrico reconstruido F1+F2+F3)
    let owner_signer = Signer::External(
        ed25519_verifier.clone(),
        Bytes::from_slice(e, &owner_ed25519.to_array()),
    );

    // Signer ZK email — key_data = email commitment (hash del email + salt)
    let zk_signer = Signer::External(
        zk_email_verifier.clone(),
        Bytes::from_slice(e, &email_commitment.to_array()),
    );

    // Signer passkey / biométrico de dispositivo (secp256r1 uncompressed 65 bytes)
    let secp_signer = Signer::External(
        secp256r1_verifier.clone(),
        Bytes::from_slice(e, &secp256r1_pubkey.to_array()),
    );

    // ── Reglas biometric-tx (una por token en tx_targets) ────────────────────
    // Transferencias normales: biométrico ed25519 + spending_limit por contrato.
    // El nombre se repite a propósito — las reglas se distinguen por su ID interno
    // y su CallContract(target). El SDK identifica cada regla por el target del context_type.
    for target in tx_targets.iter() {
        let mut signers: Vec<Signer> = Vec::new(e);
        signers.push_back(owner_signer.clone());
        let mut policies: Map<Address, Val> = Map::new(e);
        policies.set(spending_limit_policy.clone(), spending_limit_params);

        smart_account_lib::add_context_rule(
            e,
            &ContextRuleType::CallContract(target),
            &String::from_str(e, "biometric-tx"),
            None,
            &signers,
            &policies,
        );
    }

    // ── Regla admin-cfg ───────────────────────────────────────────────────────
    // Operaciones de configuración: biométrico ed25519 estricto, sin policies.
    // Cubre: cambiar signers, cambiar context rules, desactivar yield, revocar sesiones.
    {
        let mut signers: Vec<Signer> = Vec::new(e);
        signers.push_back(owner_signer.clone());
        let policies: Map<Address, Val> = Map::new(e);

        smart_account_lib::add_context_rule(
            e,
            &ContextRuleType::Default,
            &String::from_str(e, "admin-cfg"),
            None,
            &signers,
            &policies,
        );
    }

    // ── Regla zk-recovery ─────────────────────────────────────────────────────
    // Recovery por ZK proof de email. Autoriza cambiar el signer principal.
    {
        let mut signers: Vec<Signer> = Vec::new(e);
        signers.push_back(zk_signer);
        let policies: Map<Address, Val> = Map::new(e);

        smart_account_lib::add_context_rule(
            e,
            &ContextRuleType::Default,
            &String::from_str(e, "zk-recovery"),
            None,
            &signers,
            &policies,
        );
    }

    // ── Regla sep10-auth ──────────────────────────────────────────────────────
    // SEP-10 challenge-response con passkey (secp256r1). Solo auth, no transacciones.
    {
        let mut signers: Vec<Signer> = Vec::new(e);
        signers.push_back(secp_signer);
        let policies: Map<Address, Val> = Map::new(e);

        smart_account_lib::add_context_rule(
            e,
            &ContextRuleType::Default,
            &String::from_str(e, "sep10-auth"),
            None,
            &signers,
            &policies,
        );
    }

    // NOTA: la regla `yield-auto` se difiere a AcceslySmartAccount::setup_yield()
    // post-deploy para reducir el footprint del constructor y caer dentro de
    // los límites de Soroban protocol 26.
}
