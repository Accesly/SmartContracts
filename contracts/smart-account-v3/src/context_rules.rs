//! # Context Rules v3 (SmartAccount v3, 2026-06-15)
//!
//! Solo 3 reglas base — sin `zk-recovery`, sin `yield-auto`.
//!
//! | IDs       | Nombre        | ContextRuleType              | Signers              | Policies         |
//! |-----------|---------------|------------------------------|----------------------|------------------|
//! | 0 .. N-1  | biometric-tx  | CallContract(tx_target[i])   | ed25519 (External)   | spending_limit   |
//! | N         | admin-cfg     | Default                      | ed25519 (External)   | —                |
//! | N+1       | sep10-auth    | Default                      | secp256r1 (External) | —                |
//!
//! Donde `N = tx_targets.len()`. Si `tx_targets` está vacío, no se instala
//! ninguna regla biometric-tx en el constructor — el SDK puede agregarlas
//! después vía admin-cfg.
//!
//! ## Recovery
//!
//! La regla `zk-recovery` de v2-legacy se eliminó. El nuevo flujo de recovery
//! (OTP-email + password de Cognito) reconstruye la seed con F2+F3 en el
//! cliente (sin device) y firma una tx normal `rotate_signer(...)` que pasa
//! por la regla `admin-cfg`. No requiere verifier ZK on-chain.
//!
//! Ver SDKAccesly/docs/Plan_Final_v1.md §5 para el flujo completo.
//!
//! ## Reglas dinámicas (añadidas por el SDK en runtime)
//!
//! Compatibles con v3:
//!   - `session-key` (Default) — External signer (session ed25519) + session_key_policy
//!   - `allowlist-tx` (CallContract(target)) — External signer (session key) sin policy
//!   - `upgrade-rule` (Default) — session key + upgrade_rule_policy
//!
//! Incompatibles con el nuevo spec (no se agregan): blend-rule (Blend fuera de scope).

use soroban_sdk::{Address, Bytes, BytesN, Env, Map, String, Val, Vec};
use stellar_accounts::smart_account::{self as smart_account_lib, ContextRuleType, Signer};

/// Instala las 3 context rules base de SmartAccount v3.
///
/// Sin `zk-recovery` y sin `yield-auto` (la primera la reemplaza el flujo de
/// recovery v2; la segunda sale del scope).
#[allow(clippy::too_many_arguments)]
pub fn setup_context_rules(
    e: &Env,
    owner_ed25519: &BytesN<32>,
    secp256r1_pubkey: &BytesN<65>,
    ed25519_verifier: &Address,
    secp256r1_verifier: &Address,
    spending_limit_policy: &Address,
    spending_limit_params: Val,
    tx_targets: &Vec<Address>,
) {
    // ── Signers ───────────────────────────────────────────────────────────────

    // Signer ed25519 del propietario (biométrico reconstruido F1+F2+F3 o F2+F3 en recovery)
    let owner_signer = Signer::External(
        ed25519_verifier.clone(),
        Bytes::from_slice(e, &owner_ed25519.to_array()),
    );

    // Signer passkey/biométrico de dispositivo (secp256r1 uncompressed 65 bytes)
    let secp_signer = Signer::External(
        secp256r1_verifier.clone(),
        Bytes::from_slice(e, &secp256r1_pubkey.to_array()),
    );

    // ── Reglas biometric-tx (una por token en tx_targets) ────────────────────
    // Transferencias normales: biométrico ed25519 + spending_limit por contrato.
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
    // Cambios de configuración: cambiar signers, cambiar context rules,
    // upgrade, rotate_signer (recovery v2). Biométrico ed25519 estricto.
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

    // (no instalamos zk-recovery ni yield-auto — fuera de scope en v3)
}
