# Accesly — Smart Contracts

[![CI](https://github.com/Accesly/SmartContracts/actions/workflows/ci.yml/badge.svg)](https://github.com/Accesly/SmartContracts/actions/workflows/ci.yml)
[![Security](https://github.com/Accesly/SmartContracts/actions/workflows/security.yml/badge.svg)](https://github.com/Accesly/SmartContracts/actions/workflows/security.yml)

Non-custodial authentication infrastructure for Stellar. This repository contains the Soroban smart contracts that compose Accesly's on-chain layer.

**Status:** Phase 1 complete · deployed on Stellar Testnet · 139 tests passing · 6 security audit rounds (Almanax) with zero critical/high findings open.

**Latest WASM hash (testnet):** `e79d018e78ce1ae7d20dc5aecade04bb546e271dfc8a4246ac45dbfe97037a4b`

---

## Recent modifications (protocol 26 adaptation)

The Stellar testnet upgrade to **protocol 26** tightened the per-transaction Soroban footprint limits (`writeBytes` and `write_entries`). The original `Smart Account` constructor — which installed every context rule in a single tx, including `yield-auto` plus its `YieldDistributionPolicy` with 7 config keys — exceeded the new caps and aborted with `sceStorage::scecExceededLimit` (≈29 entries / ≈295 KB).

### What changed

| Area | Before | After |
|---|---|---|
| `__constructor` arity | 13 args (included `yield_policy`, `yield_params`, `cetes_contract`) | **10 args** — yield bits removed |
| `yield-auto` rule install | Happened inside `__constructor` | Deferred to a new `setup_yield(yield_policy, yield_params, cetes_contract)` public method, invoked post-deploy |
| Rules installed by constructor | 5 base (`biometric-tx × N`, `admin-cfg`, `zk-recovery`, `sep10-auth`, `yield-auto`) | **4 base** (`yield-auto` deferred) |
| Footprint of initial deploy | ~29 entries / ~295 KB → rejected | 16–22 entries depending on `tx_targets` → fits well within protocol 26 caps |
| OZ Stellar deps in [Cargo.toml](Cargo.toml) | `path = "../oz-reference/..."` (required cloning the OZ repo as sibling) | `git = "https://github.com/OpenZeppelin/stellar-contracts", tag = "v0.7.1"` — reproducible builds without an extra clone |
| New idempotency marker | — | `SmartAccountStorageKey::YieldInstalled` + error code `YieldAlreadyInstalled = 9002` |
| Integration tests | Expected 6 / 4 rules with yield baked in | Expected **5 / 3 base rules**, plus two new tests: `setup_yield_installs_yield_auto_rule` and `setup_yield_cannot_be_called_twice` |

### New API

```rust
// Called once, post-deploy, authorized by the Smart Account itself
// (covered by the admin-cfg context rule + ed25519 biometric signature).
pub fn setup_yield(
    e: &Env,
    yield_policy: Address,
    yield_params: Val,
    cetes_contract: Address,
)
```

Idempotent: a second call panics with `YieldAlreadyInstalled`. To rotate the policy, `uninstall` it via `admin-cfg` first and then re-invoke `setup_yield`.

### Operational impact

- The backend (Lambda `createWallet`) now submits the deploy tx via Soroban RPC directly (KMS-signed), bypassing the OZ Relayer image, which still ships a pre-protocol-26 `stellar-rust-sdk` that rejects valid txs with `TxSorobanInvalid`.
- A second tx (`setup_yield`) is fired only when an `appConfig` opts into CETES yield. Apps that don't use yield never pay that cost.

---

## What is Accesly?

Accesly lets developers integrate Stellar wallets into their applications with social login and biometrics, without users ever needing to know they're using blockchain. The user's private key never exists on the server: it is generated on-device, split into 3 fragments with Shamir Secret Sharing (MPC 2-of-3), and reconstructed client-side only at signing time.

The on-chain layer is composed of **3 types of contracts**:

1. **Smart Account** — one per user. Implements OpenZeppelin Stellar's `CustomAccountInterface`. Centralizes authorization via `__check_auth`.
2. **Shared verifiers** — a single deploy per network. Validate signatures (ed25519, secp256r1 / WebAuthn, ZK email).
3. **Shared policies** — a single deploy per network, isolated state per Smart Account. Enforce on-chain restrictions (spending limits, session keys, automatic yield distribution, etc.).

---

## Architecture

```
                           ┌─────────────────────────┐
                           │   User (device)         │
                           │   SDK reconstructs key  │
                           │   F1 + F2 → sign XDR    │
                           └────────────┬────────────┘
                                        │
                                        ▼ (ed25519 signature)
                           ┌─────────────────────────┐
                           │  Smart Account (1/user) │
                           │  __check_auth via OZ    │
                           └────────────┬────────────┘
                                        │
              ┌─────────────────────────┼──────────────────────────┐
              ▼                         ▼                          ▼
   ┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
   │    Verifiers     │      │     Policies     │      │   Governance     │
   │     (shared)     │      │     (shared)     │      │     (shared)     │
   ├──────────────────┤      ├──────────────────┤      ├──────────────────┤
   │ ed25519-verifier │      │ spending-limit   │      │  Timelock 48h    │
   │ secp256r1-       │      │ session-key      │      │  (upgrades +     │
   │   verifier       │      │ yield-           │      │   admin ops)     │
   │ zk-email-verif.  │      │   distribution   │      └──────────────────┘
   └──────────────────┘      │ blend-rule       │
                             │ upgrade-rule     │
                             │ blend-yield-pol. │
                             └──────────────────┘

                             ┌──────────────────┐
                             │   Blend Vault    │
                             │   (SEP-56)       │
                             │  USDC → Blend    │
                             └──────────────────┘
```

Each Smart Account references the shared verifiers and policies by address. Policies store state keyed by `(smart_account_address, context_rule_id)` so multiple users coexist in the same deploy without collision.

---

## Contracts

| # | Contract | Purpose | Deploy type |
|---|---|---|---|
| 1 | `smart-account` | User's programmable wallet. `CustomAccountInterface`, context rules, upgradeable | Per user |
| 2 | `ed25519-verifier` | Verifies ed25519 signatures of the reconstructed key | Shared |
| 3 | `secp256r1-verifier` | Verifies WebAuthn / passkey signatures (secp256r1). SEP-10 only | Shared |
| 4 | `zk-email-verifier` | DKIM registry + ZK verification of email ownership (SEP-30 recovery) | Shared |
| 5 | `spending-limit` | Per-tx cap and rolling-window accumulated cap | Shared |
| 6 | `session-key` | Temporary sessions with duration and max amount | Shared |
| 7 | `yield-distribution` | CETES 50/50 yield distribution (Etherfuse) | Shared |
| 8 | `governance` | TimelockController 48h for upgrades and admin operations | Shared |
| 9 | `blend-vault` | SEP-56 vault on top of Blend Protocol (USDC → bToken) | Shared |
| 10 | `blend-yield-policy` | Blend 60/30/10 yield distribution | Shared |
| 11 | `blend-rule` | Restricts operations to a specific Blend pool | Shared |
| 12 | `upgrade-rule` | Restricts session keys to call only `upgrade()` on a target. Includes rate limit (max 5 rules per account) | Shared |

---

## Smart Account context rules

Context rules are the permission table that `__check_auth` evaluates on every transaction. Each rule defines which signer can authorize which action and under which policy.

### Rules installed by the constructor

| ID | Name | ContextRuleType | Signer | Policy |
|---|---|---|---|---|
| 0..N-1 | `biometric-tx` | `CallContract(tx_target[i])` | ed25519 (External) | spending-limit |
| N | `admin-cfg` | `Default` | ed25519 (External) | — |
| N+1 | `zk-recovery` | `Default` | zk-email (External) | — |
| N+2 | `sep10-auth` | `Default` | secp256r1 (External) | — |

Where `N = tx_targets.len()`. One `biometric-tx` rule per token in `tx_targets`. If `tx_targets` is empty, no biometric-tx rules are installed by the constructor (the SDK can add them dynamically via `admin-cfg`).

> **Note (protocol 26):** the `yield-auto` rule was moved out of `__constructor` and is now installed by `setup_yield(...)` post-deploy. See [Recent modifications](#recent-modifications-protocol-26-adaptation) above.

**Why one rule per token:** OZ `SpendingLimit::install()` rejects any rule whose `context_type` is not `CallContract(_)`. The SDK passes the SAC addresses (USDC, EURC, MXNe, etc.) the appId wants to bring under spending-limit enforcement.

### Dynamic rules (installed by the SDK post-creation)

| Name | When created | Restriction |
|---|---|---|
| `session-key` | User opens a temporary session | session-key policy: duration + max amount |
| `allowlist-tx` | Before interacting with a third-party contract | `CallContract(target)` — no policy, only restricts destination contract |
| `blend-rule` | Before operating on Blend | blend-rule policy: pool + request types + amount |
| `upgrade-rule` | Before a scheduled upgrade | upgrade-rule policy: only `upgrade()` function. Max 5 active per account |

---

## Upgrade flow

Smart Account upgrades are protected by the TimelockController:

1. The Accesly team calls `governance.schedule(target=smart_account, fn="upgrade", new_wasm_hash, delay=48h)`.
2. ~34,560 ledgers (~48h) pass. During this period anyone can verify the pending upgrade on-chain or cancel it if they hold the canceller role.
3. The team calls `governance.execute(...)`. The timelock invokes `smart_account.upgrade(new_wasm_hash, operator)`.
4. The `admin-cfg` context rule validates that the caller is the authorized timelock.

---

## Local setup

**Requirements:**

- Rust stable with `wasm32v1-none` target (managed by [rust-toolchain.toml](rust-toolchain.toml))
- [Stellar CLI](https://developers.stellar.org/docs/build/smart-contracts/getting-started/setup) v26.x
- OZ Stellar `v0.7.1` is now consumed via git in [Cargo.toml](Cargo.toml) (`git = "https://github.com/OpenZeppelin/stellar-contracts", tag = "v0.7.1"`). No extra clone needed — `cargo build` fetches it automatically.

**Verify setup:**

```bash
rustup target list --installed | grep wasm32v1-none
stellar --version  # must be 26.x
```

---

## Build

```bash
cargo build --target wasm32v1-none --release
```

The compiled WASM files go to `target/wasm32v1-none/release/accesly_*.wasm`. The `release` profile is configured with `opt-level = "z"`, `lto = true`, `codegen-units = 1`, and `panic = "abort"` to minimize size.

---

## Tests

**Unit tests** (per contract):

```bash
cargo test --workspace
```

Each contract has its own suite under `contracts/<name>/src/contract.rs` (inside `#[cfg(test)] mod tests`). Snapshots live in `contracts/<name>/test_snapshots/`.

**Cross-contract integration tests:**

```bash
cargo test -p accesly-integration-tests
```

The e2e suite in `contracts/integration-tests/` exercises real combinations: Smart Account + verifiers + policies in a single `Env`. Covers critical flows (full constructor wiring, zk-recovery hard-fail regression lock).

**Current status:** 139 tests passing, 0 failing, 0 ignored.

---

## Deploy to testnet

```bash
chmod +x scripts/deploy_testnet.sh
./scripts/deploy_testnet.sh
```

The script:

1. Creates (or reuses) the `accesly-deployer` identity in the Stellar CLI.
2. Funds the account via Friendbot (10,000 XLM testnet).
3. Auto-detects `USDC_RESERVE_INDEX` from the Blend TestnetV2 pool.
4. Deploys the 11 shared contracts and uploads the Smart Account WASM.
5. Writes addresses to `scripts/deployed_addresses.env`.

**External addresses used** (testnet, do not change):

| Resource | Address |
|---|---|
| Blend TestnetV2 pool | `CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF` |
| USDC SAC (Circle) | `CAQCFVLOBK5GIULPNZRGATJJMIZL5BSP7X5YJVMGCPTUEPFM4AVSRCJU` |
| CETES SAC | `CC72F57YTPX76HAA64JQOEGHQAPSADQWSY5DWVBR66JINPFDLNCQYHIC` |

---

## Post-deploy manual steps

After running the deploy script:

### 1. Initialize `blend-yield-policy`

Due to a Stellar CLI v26 bug with OZ Policy contracts + `Address` args, `stellar contract invoke -- init` fails with `Missing Entry Context`. Workaround: invoke `init()` through a TypeScript script that builds the transaction manually with `@stellar/stellar-sdk`.

```bash
cd scripts/blend-yield-init
npm install
POLICY_ADDRESS=<blend-yield-policy address> \
  ACCESLY_WALLET=<accesly-deployer address> \
  SECRET_KEY=$(stellar keys secret accesly-deployer) \
  npm start
```

The script reads env vars, builds the `InvokeHostFunctionOp` invoking `init(accesly_wallet)`, signs and submits it. See [scripts/blend-yield-init/README.md](scripts/blend-yield-init/README.md) for details.

### 2. Register DKIM keys in `zk-email-verifier`

```bash
stellar contract invoke --id $ZK_EMAIL_VERIFIER \
  --source-account accesly-deployer --network testnet \
  -- set_dkim_public_key_hash \
  --domain_hash <sha256_of_domain_hex> \
  --public_key_hash <sha256_of_dkim_public_key_hex> \
  --operator $ACCESLY_DEPLOYER
```

Repeat for each domain (gmail.com, outlook.com, etc.) you want to enable for recovery.

### 3. Configure the Backend Lambdas

The Lambda `createWallet` needs `BLEND_VAULT`, `BLEND_YIELD_POLICY`, `SMART_ACCOUNT_WASM_HASH`, and the rest of the addresses. See `scripts/deployed_addresses.env`.

---

## Known technical debt

- **`zk-email-verifier.verify()` returns `false` always** (intentional hard-fail). Requires integrating a groth16/plonk verifier from Accesly's zkEmail circuit (Phase 2). Until then, recovery via ZK email does not authorize anything — secure but not functional. This decision closes the critical vulnerability reported in the Almanax scan of Apr 27. See open issues for tracking.
- **`yield-auto` with empty signers.** The constructor accepts `Vec<Address>::new()`. When the OpenZeppelin Relayer is contracted, register its address as a fixed signer.
- **`blend-rule` and `allowlist-tx` are installed dynamically from the SDK**, not in the Smart Account constructor. SDK change, not a contract change.
- **CLI v26 + OZ Policy + Address args.** Bug affecting all policies; mitigated with the TS init script (`scripts/blend-yield-init/`).
- **Timelock with `proposer == executor == admin` on testnet.** Blocking item for mainnet — rotate to 3-of-3 multisig with hardware wallets before going live.

See open GitHub issues for full tracking.

---

## Security

- **6 Almanax scans** executed. All critical and high findings resolved or formally accepted with documented justification.
- **CI**: `.github/workflows/ci.yml` runs fmt + clippy + WASM build + tests + WASM size check on every PR. `.github/workflows/security.yml` runs `cargo audit`, license check (`cargo-deny`), and secret scanning (`gitleaks`).
- **Reproducible OZ dependencies:** all `stellar-*` packages pinned to `=0.7.1` (workspace `Cargo.toml`).
- **Workspace-wide overflow checks** in release profile (`overflow-checks = true`).

For audit context, contact the team.

---

## Repository structure

```
accesly-contracts/
├── Cargo.toml                       # workspace manifest
├── rust-toolchain.toml              # stable + wasm32v1-none
├── deny.toml                        # cargo-deny license policy
├── .github/workflows/               # CI + security
├── contracts/
│   ├── smart-account/               # per-user, CustomAccountInterface
│   ├── ed25519-verifier/            # shared
│   ├── secp256r1-verifier/          # shared (WebAuthn)
│   ├── zk-email-verifier/           # shared (DKIM + ZK)
│   ├── spending-limit/              # shared policy
│   ├── session-key/                 # shared policy
│   ├── yield-distribution/          # shared policy (CETES 50/50)
│   ├── governance/                  # shared (Timelock 48h)
│   ├── blend-vault/                 # shared (SEP-56 vault)
│   ├── blend-yield-policy/          # shared policy (Blend 60/30/10)
│   ├── blend-rule/                  # shared policy
│   ├── upgrade-rule/                # shared policy (rate-limited)
│   └── integration-tests/           # e2e cross-contract tests
└── scripts/
    ├── deploy_testnet.sh
    ├── deployed_addresses.env       # generated by deploy_testnet.sh
    └── blend-yield-init/            # workaround for CLI v26 bug
```

---

## License

MIT. See workspace [Cargo.toml](Cargo.toml).
