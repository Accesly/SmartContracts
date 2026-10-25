//! # Accesly — x402 Spending Policy
//!
//! Política de gasto para cobros x402 (pagos por uso en USDC). Se instala en
//! la context rule del session key con el que un cliente paga a un agente, y
//! rechaza on-chain cualquier pago fuera de política. Los límites los impone
//! el contrato, no el backend de Accesly.
//!
//! Reglas que valida `enforce`, en este orden:
//! 1. Solo `transfer(from, to, amount)` (SEP-41) sobre el token configurado
//!    (USDC SAC). Cualquier otra función o token se rechaza.
//! 2. `from` debe ser el propio Smart Account y `amount` debe ser > 0.
//! 3. Tope por request: `amount <= max_per_request`.
//! 4. Allowlist: `to` debe estar en la lista de destinatarios permitidos.
//! 5. Tope mensual: el gasto acumulado en la ventana actual más `amount` no
//!    puede superar `monthly_cap`. La ventana es fija, de `period_ledgers`
//!    (518400 ≈ 30 días); al vencer, el acumulado vuelve a cero.
//!
//! Cada rechazo tiene su propio código de error para que el reporte de tests
//! y el explorer muestren qué regla se disparó.
//!
//! Las funciones de administración (`set_caps`, `add_allowed`,
//! `remove_allowed`) requieren auth del Smart Account, o sea la firma MPC del
//! dueño de la wallet. El session key no puede cambiar sus propios límites.
use soroban_sdk::{
    auth::{Context, ContractContext},
    contract, contracterror, contractimpl, contracttype, panic_with_error, Address, Env, Symbol,
    TryFromVal, Vec,
};
use stellar_accounts::{
    policies::Policy,
    smart_account::{ContextRule, Signer},
};

// ── Constantes ───────────────────────────────────────────────────────────────

const DAY_IN_LEDGERS: u32 = 17280;
const EXTEND_AMOUNT: u32 = 60 * DAY_IN_LEDGERS;
const TTL_THRESHOLD: u32 = EXTEND_AMOUNT - DAY_IN_LEDGERS;

/// Ventana mensual sugerida: 30 días en ledgers.
pub const MONTH_IN_LEDGERS: u32 = 30 * DAY_IN_LEDGERS;

/// Máximo de destinatarios en la allowlist, para acotar el costo de `enforce`.
pub const MAX_ALLOWLIST: u32 = 20;

// ── Errores ──────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum X402PolicyError {
    /// No hay política instalada para esta cuenta y context rule.
    NotInstalled = 10000,
    /// Ya existe una política para esta context rule.
    AlreadyInstalled = 10001,
    /// Parámetros inválidos (topes <= 0, tope por request > mensual, ventana 0).
    InvalidParams = 10002,
    /// El contexto no es una llamada a contrato o la función no es `transfer`.
    FunctionNotAllowed = 10003,
    /// La transferencia es de un token distinto al configurado.
    WrongToken = 10004,
    /// Argumentos de `transfer` ilegibles, `from` distinto al Smart Account o
    /// destinatario muxed.
    InvalidTransfer = 10005,
    /// Monto cero o negativo.
    InvalidAmount = 10006,
    /// El pago supera el tope por request.
    PerRequestCapExceeded = 10007,
    /// El destinatario no está en la allowlist.
    RecipientNotAllowed = 10008,
    /// El pago supera el tope mensual acumulado.
    MonthlyCapExceeded = 10009,
    /// La allowlist llegó al máximo de entradas.
    AllowlistFull = 10010,
}

// ── Storage ──────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
enum StorageKey {
    Policy(Address, u32), // (smart_account, context_rule_id)
}

/// Estado de la política para un Smart Account y una context rule.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct X402PolicyData {
    /// Contrato del token permitido (USDC SAC).
    pub token: Address,
    /// Monto máximo por pago, en unidades mínimas del token.
    pub max_per_request: i128,
    /// Gasto máximo acumulado por ventana.
    pub monthly_cap: i128,
    /// Duración de la ventana en ledgers.
    pub period_ledgers: u32,
    /// Destinatarios permitidos.
    pub allowlist: Vec<Address>,
    /// Ledger en que empezó la ventana actual.
    pub window_start: u32,
    /// Gasto acumulado en la ventana actual.
    pub window_spent: i128,
}

// ── Parámetros de instalación ─────────────────────────────────────────────────

/// Parámetros que el Smart Account envía al instalar la política.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct X402PolicyInstallParams {
    pub token: Address,
    pub max_per_request: i128,
    pub monthly_cap: i128,
    pub period_ledgers: u32,
    pub allowlist: Vec<Address>,
}

// ── Helpers de storage ────────────────────────────────────────────────────────

fn storage_key(smart_account: &Address, context_rule_id: u32) -> StorageKey {
    StorageKey::Policy(smart_account.clone(), context_rule_id)
}

fn load(e: &Env, smart_account: &Address, context_rule_id: u32) -> X402PolicyData {
    match e
        .storage()
        .persistent()
        .get::<StorageKey, X402PolicyData>(&storage_key(smart_account, context_rule_id))
    {
        Some(data) => data,
        None => panic_with_error!(e, X402PolicyError::NotInstalled),
    }
}

fn save(e: &Env, smart_account: &Address, context_rule_id: u32, data: &X402PolicyData) {
    let key = storage_key(smart_account, context_rule_id);
    e.storage().persistent().set(&key, data);
    e.storage()
        .persistent()
        .extend_ttl(&key, TTL_THRESHOLD, EXTEND_AMOUNT);
}

fn validate_caps(e: &Env, max_per_request: i128, monthly_cap: i128, period_ledgers: u32) {
    if max_per_request <= 0 || monthly_cap <= 0 || max_per_request > monthly_cap {
        panic_with_error!(e, X402PolicyError::InvalidParams);
    }
    if period_ledgers == 0 {
        panic_with_error!(e, X402PolicyError::InvalidParams);
    }
}

/// Lee `(from, to, amount)` de un contexto `transfer` sobre el token configurado.
fn parse_transfer(e: &Env, context: &Context, token: &Address) -> (Address, Address, i128) {
    let ContractContext {
        contract,
        fn_name,
        args,
    } = match context {
        Context::Contract(c) => c,
        _ => panic_with_error!(e, X402PolicyError::FunctionNotAllowed),
    };
    if fn_name != &Symbol::new(e, "transfer") {
        panic_with_error!(e, X402PolicyError::FunctionNotAllowed);
    }
    if contract != token {
        panic_with_error!(e, X402PolicyError::WrongToken);
    }
    if args.len() != 3 {
        panic_with_error!(e, X402PolicyError::InvalidTransfer);
    }
    // Un destinatario muxed no se decodifica como Address y se rechaza: la
    // allowlist compara cuentas, no sub-cuentas.
    let from = Address::try_from_val(e, &args.get_unchecked(0))
        .unwrap_or_else(|_| panic_with_error!(e, X402PolicyError::InvalidTransfer));
    let to = Address::try_from_val(e, &args.get_unchecked(1))
        .unwrap_or_else(|_| panic_with_error!(e, X402PolicyError::InvalidTransfer));
    let amount = i128::try_from_val(e, &args.get_unchecked(2))
        .unwrap_or_else(|_| panic_with_error!(e, X402PolicyError::InvalidTransfer));
    (from, to, amount)
}

// ── Contrato ──────────────────────────────────────────────────────────────────

#[contract]
pub struct X402SpendingPolicy;

#[contractimpl]
impl Policy for X402SpendingPolicy {
    type AccountParams = X402PolicyInstallParams;

    /// Valida token, función, tope por request, allowlist y tope mensual, y
    /// acumula el gasto de la ventana.
    fn enforce(
        e: &Env,
        context: Context,
        _authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        // Liga enforce al flujo de auth del SA: evita llamadas externas directas.
        smart_account.require_auth();

        let mut data = load(e, &smart_account, context_rule.id);
        let (from, to, amount) = parse_transfer(e, &context, &data.token);

        if from != smart_account {
            panic_with_error!(e, X402PolicyError::InvalidTransfer);
        }
        if amount <= 0 {
            panic_with_error!(e, X402PolicyError::InvalidAmount);
        }
        if amount > data.max_per_request {
            panic_with_error!(e, X402PolicyError::PerRequestCapExceeded);
        }
        if !data.allowlist.contains(&to) {
            panic_with_error!(e, X402PolicyError::RecipientNotAllowed);
        }

        let current = e.ledger().sequence();
        if current >= data.window_start.saturating_add(data.period_ledgers) {
            data.window_start = current;
            data.window_spent = 0;
        }
        let new_spent = data
            .window_spent
            .checked_add(amount)
            .unwrap_or_else(|| panic_with_error!(e, X402PolicyError::MonthlyCapExceeded));
        if new_spent > data.monthly_cap {
            panic_with_error!(e, X402PolicyError::MonthlyCapExceeded);
        }
        data.window_spent = new_spent;
        save(e, &smart_account, context_rule.id, &data);
    }

    /// Inicializa la política con topes, token y allowlist.
    fn install(
        e: &Env,
        install_params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();
        if e.storage()
            .persistent()
            .has(&storage_key(&smart_account, context_rule.id))
        {
            panic_with_error!(e, X402PolicyError::AlreadyInstalled);
        }
        validate_caps(
            e,
            install_params.max_per_request,
            install_params.monthly_cap,
            install_params.period_ledgers,
        );
        if install_params.allowlist.len() > MAX_ALLOWLIST {
            panic_with_error!(e, X402PolicyError::AllowlistFull);
        }
        let data = X402PolicyData {
            token: install_params.token,
            max_per_request: install_params.max_per_request,
            monthly_cap: install_params.monthly_cap,
            period_ledgers: install_params.period_ledgers,
            allowlist: install_params.allowlist,
            window_start: e.ledger().sequence(),
            window_spent: 0,
        };
        save(e, &smart_account, context_rule.id, &data);
    }

    /// Elimina la política.
    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();
        let key = storage_key(&smart_account, context_rule.id);
        if !e.storage().persistent().has(&key) {
            panic_with_error!(e, X402PolicyError::NotInstalled);
        }
        e.storage().persistent().remove(&key);
    }
}

#[contractimpl]
impl X402SpendingPolicy {
    /// Consulta el estado de la política (lectura pública).
    pub fn get_data(e: Env, context_rule_id: u32, smart_account: Address) -> X402PolicyData {
        load(&e, &smart_account, context_rule_id)
    }

    /// Indica si hay política instalada para esta cuenta y regla.
    pub fn is_installed(e: Env, context_rule_id: u32, smart_account: Address) -> bool {
        e.storage()
            .persistent()
            .has(&storage_key(&smart_account, context_rule_id))
    }

    /// Cambia los topes. Requiere auth del Smart Account. No reinicia la ventana.
    pub fn set_caps(
        e: Env,
        context_rule_id: u32,
        smart_account: Address,
        max_per_request: i128,
        monthly_cap: i128,
    ) {
        smart_account.require_auth();
        let mut data = load(&e, &smart_account, context_rule_id);
        validate_caps(&e, max_per_request, monthly_cap, data.period_ledgers);
        data.max_per_request = max_per_request;
        data.monthly_cap = monthly_cap;
        save(&e, &smart_account, context_rule_id, &data);
    }

    /// Agrega un destinatario a la allowlist. Requiere auth del Smart Account.
    pub fn add_allowed(e: Env, context_rule_id: u32, smart_account: Address, recipient: Address) {
        smart_account.require_auth();
        let mut data = load(&e, &smart_account, context_rule_id);
        if data.allowlist.contains(&recipient) {
            return;
        }
        if data.allowlist.len() >= MAX_ALLOWLIST {
            panic_with_error!(&e, X402PolicyError::AllowlistFull);
        }
        data.allowlist.push_back(recipient);
        save(&e, &smart_account, context_rule_id, &data);
    }

    /// Quita un destinatario de la allowlist. Requiere auth del Smart Account.
    pub fn remove_allowed(
        e: Env,
        context_rule_id: u32,
        smart_account: Address,
        recipient: Address,
    ) {
        smart_account.require_auth();
        let mut data = load(&e, &smart_account, context_rule_id);
        if let Some(i) = data.allowlist.first_index_of(&recipient) {
            data.allowlist.remove(i);
            save(&e, &smart_account, context_rule_id, &data);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;

    use soroban_sdk::{
        auth::{Context, ContractContext},
        contract, symbol_short,
        testutils::{Address as _, Ledger},
        vec, Address, Env, IntoVal, String, Symbol, Vec,
    };
    use stellar_accounts::smart_account::{ContextRule, ContextRuleType};

    use super::*;

    #[contract]
    struct MockContract;

    /// 1 USDC = 10^7 unidades (7 decimales en Stellar).
    const CENT: i128 = 100_000;

    struct Setup {
        e: Env,
        policy: Address,
        account: Address,
        token: Address,
        merchant: Address,
        rule: ContextRule,
    }

    fn make_rule(e: &Env) -> ContextRule {
        ContextRule {
            id: 2,
            context_type: ContextRuleType::Default,
            name: String::from_str(e, "x402-session"),
            signers: Vec::new(e),
            signer_ids: Vec::new(e),
            policies: Vec::new(e),
            policy_ids: Vec::new(e),
            valid_until: None,
        }
    }

    /// Instala la política: tope de 0.05 USDC por request, 0.10 USDC por
    /// ventana de 100 ledgers, y un solo comercio en la allowlist.
    fn setup() -> Setup {
        let e = Env::default();
        let policy = e.register(MockContract, ());
        let account = Address::generate(&e);
        let token = Address::generate(&e);
        let merchant = Address::generate(&e);
        let rule = make_rule(&e);
        e.ledger().with_mut(|l| l.sequence_number = 1000);
        e.mock_all_auths();
        e.as_contract(&policy, || {
            X402SpendingPolicy::install(
                &e,
                X402PolicyInstallParams {
                    token: token.clone(),
                    max_per_request: 5 * CENT,
                    monthly_cap: 10 * CENT,
                    period_ledgers: 100,
                    allowlist: vec![&e, merchant.clone()],
                },
                rule.clone(),
                account.clone(),
            );
        });
        Setup {
            e,
            policy,
            account,
            token,
            merchant,
            rule,
        }
    }

    fn ctx(
        e: &Env,
        token: &Address,
        fn_name: Symbol,
        from: &Address,
        to: &Address,
        amount: i128,
    ) -> Context {
        let mut args = soroban_sdk::Vec::new(e);
        args.push_back(from.into_val(e));
        args.push_back(to.into_val(e));
        args.push_back(amount.into_val(e));
        Context::Contract(ContractContext {
            contract: token.clone(),
            fn_name,
            args,
        })
    }

    fn pay(s: &Setup, to: &Address, amount: i128) {
        let c = ctx(
            &s.e,
            &s.token,
            symbol_short!("transfer"),
            &s.account,
            to,
            amount,
        );
        s.e.as_contract(&s.policy, || {
            X402SpendingPolicy::enforce(&s.e, c, Vec::new(&s.e), s.rule.clone(), s.account.clone());
        });
    }

    fn spent(s: &Setup) -> i128 {
        s.e.as_contract(&s.policy, || {
            X402SpendingPolicy::get_data(s.e.clone(), s.rule.id, s.account.clone()).window_spent
        })
    }

    // ── pagos dentro de política ──────────────────────────────────────────────

    #[test]
    fn payment_within_policy_passes() {
        let s = setup();
        pay(&s, &s.merchant, CENT);
        pay(&s, &s.merchant, CENT);
        pay(&s, &s.merchant, CENT);
        assert_eq!(spent(&s), 3 * CENT);
    }

    #[test]
    fn payment_exactly_at_caps_passes() {
        let s = setup();
        pay(&s, &s.merchant, 5 * CENT);
        pay(&s, &s.merchant, 5 * CENT);
        assert_eq!(spent(&s), 10 * CENT);
    }

    // ── tope por request ──────────────────────────────────────────────────────

    #[test]
    #[should_panic(expected = "Error(Contract, #10007)")]
    fn reject_per_request_cap() {
        let s = setup();
        pay(&s, &s.merchant, 5 * CENT + 1);
    }

    // ── tope mensual ──────────────────────────────────────────────────────────

    #[test]
    #[should_panic(expected = "Error(Contract, #10009)")]
    fn reject_monthly_cap_accumulated() {
        let s = setup();
        pay(&s, &s.merchant, 4 * CENT);
        pay(&s, &s.merchant, 4 * CENT);
        // 8 + 4 = 12 > 10
        pay(&s, &s.merchant, 4 * CENT);
    }

    #[test]
    fn window_resets_after_period() {
        let s = setup();
        pay(&s, &s.merchant, 5 * CENT);
        pay(&s, &s.merchant, 5 * CENT);
        s.e.ledger().with_mut(|l| l.sequence_number = 1100);
        pay(&s, &s.merchant, 5 * CENT);
        assert_eq!(spent(&s), 5 * CENT);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #10009)")]
    fn window_does_not_reset_before_period() {
        let s = setup();
        pay(&s, &s.merchant, 5 * CENT);
        pay(&s, &s.merchant, 5 * CENT);
        s.e.ledger().with_mut(|l| l.sequence_number = 1099);
        pay(&s, &s.merchant, CENT);
    }

    // ── allowlist ─────────────────────────────────────────────────────────────

    #[test]
    #[should_panic(expected = "Error(Contract, #10008)")]
    fn reject_recipient_not_allowlisted() {
        let s = setup();
        let stranger = Address::generate(&s.e);
        pay(&s, &stranger, CENT);
    }

    #[test]
    fn add_allowed_enables_recipient() {
        let s = setup();
        let second = Address::generate(&s.e);
        s.e.as_contract(&s.policy, || {
            X402SpendingPolicy::add_allowed(
                s.e.clone(),
                s.rule.id,
                s.account.clone(),
                second.clone(),
            );
        });
        pay(&s, &second, CENT);
        assert_eq!(spent(&s), CENT);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #10008)")]
    fn remove_allowed_blocks_recipient() {
        let s = setup();
        s.e.as_contract(&s.policy, || {
            X402SpendingPolicy::remove_allowed(
                s.e.clone(),
                s.rule.id,
                s.account.clone(),
                s.merchant.clone(),
            );
        });
        pay(&s, &s.merchant, CENT);
    }

    // ── token y función ───────────────────────────────────────────────────────

    #[test]
    #[should_panic(expected = "Error(Contract, #10004)")]
    fn reject_wrong_token() {
        let s = setup();
        let other_token = Address::generate(&s.e);
        let c = ctx(
            &s.e,
            &other_token,
            symbol_short!("transfer"),
            &s.account,
            &s.merchant,
            CENT,
        );
        s.e.as_contract(&s.policy, || {
            X402SpendingPolicy::enforce(&s.e, c, Vec::new(&s.e), s.rule.clone(), s.account.clone());
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #10003)")]
    fn reject_approve() {
        let s = setup();
        let c = ctx(
            &s.e,
            &s.token,
            Symbol::new(&s.e, "approve"),
            &s.account,
            &s.merchant,
            CENT,
        );
        s.e.as_contract(&s.policy, || {
            X402SpendingPolicy::enforce(&s.e, c, Vec::new(&s.e), s.rule.clone(), s.account.clone());
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #10003)")]
    fn reject_transfer_from() {
        let s = setup();
        let c = ctx(
            &s.e,
            &s.token,
            Symbol::new(&s.e, "transfer_from"),
            &s.account,
            &s.merchant,
            CENT,
        );
        s.e.as_contract(&s.policy, || {
            X402SpendingPolicy::enforce(&s.e, c, Vec::new(&s.e), s.rule.clone(), s.account.clone());
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #10005)")]
    fn reject_from_other_account() {
        let s = setup();
        let other = Address::generate(&s.e);
        let c = ctx(
            &s.e,
            &s.token,
            symbol_short!("transfer"),
            &other,
            &s.merchant,
            CENT,
        );
        s.e.as_contract(&s.policy, || {
            X402SpendingPolicy::enforce(&s.e, c, Vec::new(&s.e), s.rule.clone(), s.account.clone());
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #10006)")]
    fn reject_zero_amount() {
        let s = setup();
        pay(&s, &s.merchant, 0);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #10006)")]
    fn reject_negative_amount() {
        let s = setup();
        pay(&s, &s.merchant, -CENT);
    }

    // ── administración ────────────────────────────────────────────────────────

    #[test]
    fn set_caps_updates_limits() {
        let s = setup();
        s.e.as_contract(&s.policy, || {
            X402SpendingPolicy::set_caps(
                s.e.clone(),
                s.rule.id,
                s.account.clone(),
                20 * CENT,
                50 * CENT,
            );
        });
        pay(&s, &s.merchant, 20 * CENT);
        assert_eq!(spent(&s), 20 * CENT);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #10002)")]
    fn set_caps_rejects_per_request_above_monthly() {
        let s = setup();
        s.e.as_contract(&s.policy, || {
            X402SpendingPolicy::set_caps(
                s.e.clone(),
                s.rule.id,
                s.account.clone(),
                50 * CENT,
                20 * CENT,
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #10001)")]
    fn install_twice_fails() {
        let s = setup();
        s.e.as_contract(&s.policy, || {
            X402SpendingPolicy::install(
                &s.e,
                X402PolicyInstallParams {
                    token: s.token.clone(),
                    max_per_request: CENT,
                    monthly_cap: CENT,
                    period_ledgers: 100,
                    allowlist: Vec::new(&s.e),
                },
                s.rule.clone(),
                s.account.clone(),
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #10000)")]
    fn enforce_without_install_fails() {
        let s = setup();
        let other_rule = ContextRule {
            id: 9,
            ..s.rule.clone()
        };
        let c = ctx(
            &s.e,
            &s.token,
            symbol_short!("transfer"),
            &s.account,
            &s.merchant,
            CENT,
        );
        s.e.as_contract(&s.policy, || {
            X402SpendingPolicy::enforce(&s.e, c, Vec::new(&s.e), other_rule, s.account.clone());
        });
    }

    #[test]
    fn uninstall_removes_policy() {
        let s = setup();
        s.e.as_contract(&s.policy, || {
            X402SpendingPolicy::uninstall(&s.e, s.rule.clone(), s.account.clone());
            assert!(!X402SpendingPolicy::is_installed(
                s.e.clone(),
                s.rule.id,
                s.account.clone()
            ));
        });
    }

    // ── auth del Smart Account requerida (contrato registrado, sin mock) ──────

    fn registered() -> (Env, X402SpendingPolicyClient<'static>, Address, Address) {
        let e = Env::default();
        let id = e.register(X402SpendingPolicy, ());
        let client = X402SpendingPolicyClient::new(&e, &id);
        let account = Address::generate(&e);
        let token = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();
        client.install(
            &X402PolicyInstallParams {
                token: token.clone(),
                max_per_request: 5 * CENT,
                monthly_cap: 10 * CENT,
                period_ledgers: 100,
                allowlist: Vec::new(&e),
            },
            &rule,
            &account,
        );
        e.set_auths(&[]);
        (e, client, account, token)
    }

    #[test]
    #[should_panic(expected = "Error(Auth, InvalidAction)")]
    fn set_caps_requires_smart_account_auth() {
        let (_e, client, account, _) = registered();
        client.set_caps(&2, &account, &(100 * CENT), &(100 * CENT));
    }

    #[test]
    #[should_panic(expected = "Error(Auth, InvalidAction)")]
    fn add_allowed_requires_smart_account_auth() {
        let (e, client, account, _) = registered();
        client.add_allowed(&2, &account, &Address::generate(&e));
    }

    #[test]
    #[should_panic(expected = "Error(Auth, InvalidAction)")]
    fn remove_allowed_requires_smart_account_auth() {
        let (e, client, account, _) = registered();
        client.remove_allowed(&2, &account, &Address::generate(&e));
    }

    #[test]
    #[should_panic(expected = "Error(Auth, InvalidAction)")]
    fn enforce_requires_smart_account_auth() {
        let (e, client, account, token) = registered();
        let merchant = Address::generate(&e);
        let c = ctx(
            &e,
            &token,
            symbol_short!("transfer"),
            &account,
            &merchant,
            CENT,
        );
        client.enforce(&c, &Vec::new(&e), &make_rule(&e), &account);
    }

    #[test]
    fn get_data_is_public() {
        let (_e, client, account, _) = registered();
        let data = client.get_data(&2, &account);
        assert_eq!(data.max_per_request, 5 * CENT);
        assert_eq!(data.monthly_cap, 10 * CENT);
        assert_eq!(data.window_spent, 0);
    }
}
