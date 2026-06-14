#!/usr/bin/env bash
# Deploy del zk-email-verifier v2 (Groth16 BLS12-381 con Almanax bindings).
#
# v1 era un stub que retornaba false siempre (hard-fail intencional, BL-01).
# v2 verifica criptográficamente proofs reales del circuito accesly-zkemail.
#
# Pre-requisitos:
#   1. La ceremony BLS12-381 ya terminó (zkey + vk.json en accesly-zkemail/circuits/build/).
#   2. El export_vk.ts del repo accesly-zkemail emitió `vk_for_deploy.json`
#      con las negaciones G2 pre-computadas (alpha_neg / gamma_neg / delta_neg).
#   3. El wasm del contrato fue compilado: `cargo build -p accesly-zk-email-verifier --target wasm32v1-none --release`.
#
# Uso:
#   bash scripts/deploy_zk_email_verifier_v2.sh \
#     --network testnet \
#     --vk-json /path/to/vk_for_deploy.json \
#     --admin-account accesly-deploy-testnet \
#     --admin-address GACCESLY...
#
# Output:
#   - El contrato se despliega a una NUEVA address (Soroban no soporta
#     redeploy en la misma address; los wallets v1 quedan apuntando al stub
#     viejo). El alias `accesly-zk-email-verifier-v2` queda registrado.
#   - El address se imprime a stdout para que el operador lo ponga en
#     deployed_addresses.env + DeployedResources del repo CloudServices.

set -euo pipefail

NETWORK="testnet"
VK_JSON=""
ADMIN_ACCOUNT=""
ADMIN_ADDRESS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --network) NETWORK="$2"; shift 2 ;;
    --vk-json) VK_JSON="$2"; shift 2 ;;
    --admin-account) ADMIN_ACCOUNT="$2"; shift 2 ;;
    --admin-address) ADMIN_ADDRESS="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$VK_JSON" ]] || [[ ! -f "$VK_JSON" ]]; then
  echo "error: --vk-json must point to an existing vk_for_deploy.json" >&2
  exit 1
fi
if [[ -z "$ADMIN_ACCOUNT" ]]; then
  echo "error: --admin-account is required (stellar-cli alias of the signer)" >&2
  exit 1
fi
if [[ -z "$ADMIN_ADDRESS" ]]; then
  echo "error: --admin-address is required (the G... address that will admin the verifier)" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WASM="$REPO_ROOT/target/wasm32v1-none/release/accesly_zk_email_verifier.wasm"

if [[ ! -f "$WASM" ]]; then
  echo "error: $WASM not found. Run:" >&2
  echo "  cargo build -p accesly-zk-email-verifier --target wasm32v1-none --release" >&2
  exit 1
fi

VK=$(cat "$VK_JSON")
ALIAS="accesly-zk-email-verifier-v2"

echo "==> Desplegando $ALIAS to $NETWORK"
echo "    wasm:  $WASM"
echo "    admin: $ADMIN_ADDRESS"
echo "    vk:    $VK_JSON (ic.length=$(echo "$VK" | grep -oE '"[0-9a-f]+"' | wc -l))"
echo

stellar contract deploy \
  --wasm "$WASM" \
  --source-account "$ADMIN_ACCOUNT" \
  --network "$NETWORK" \
  --alias "$ALIAS" \
  --ignore-checks \
  -- \
  --admin "$ADMIN_ADDRESS" \
  --vk "$VK"

NEW_ADDR=$(stellar contract alias show --alias "$ALIAS" --network "$NETWORK" 2>/dev/null || true)
echo
echo "==> Done"
echo "    zk-email-verifier-v2 → $NEW_ADDR"
echo
echo "Próximos pasos manuales:"
echo "  1. Actualizar deployed_addresses.env (líneas ZK_EMAIL_VERIFIER y/o ZK_EMAIL_VERIFIER_V2)"
echo "  2. Actualizar CloudServices-accesly/docs/Deployed_Resources_dev.md"
echo "  3. Registrar DKIM keys de Gmail con set_dkim_public_key_hash"
echo "  4. Smart Accounts v1 quedan apuntando al verifier stub viejo —"
echo "     migración manual o re-onboarding para activar recovery"
