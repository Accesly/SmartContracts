# blend-yield-init

Workaround for a Stellar CLI v26 bug.

## The bug

`stellar contract invoke -- init --accesly_wallet <addr>` against
`blend-yield-policy` (or any OZ Policy contract that takes an `Address` arg)
fails with:

```
error: Missing Entry Context
```

The bug is in the CLI's argument parser for OZ Policy contracts when an
`Address` parameter is involved. It's tracked upstream; until it lands we
build the `InvokeHostFunctionOp` manually with `@stellar/stellar-sdk` and
submit it via `soroban-rpc`. The contract itself is correct.

## What this script does

Calls `BlendYieldPolicy::init(accesly_wallet: Address)` once. The contract
stores the canonical accesly wallet in instance storage and panics on
re-entry (`AlreadyInitialized = 9001`), so running this twice is safe.

## Usage

```bash
cd scripts/blend-yield-init
npm install

POLICY_ADDRESS=CAKDQ7QOYHDSGXXA2HIND7U6777LQ3F3PSAUPXY3K3FBWZNN67GPXL5I \
  ACCESLY_WALLET=GD27WU6FUFV47GNIZ2VDM5PO63GZ3L2RC2ECLKNO7A557V7GOEJ3KLW3 \
  SECRET_KEY=S... \
  npm start
```

Read `POLICY_ADDRESS` from `scripts/deployed_addresses.env`
(`BLEND_YIELD_POLICY`). Read `ACCESLY_WALLET` from `ACCESLY_DEPLOYER` in the
same file (or another wallet if you want a different canonical recipient).

`SECRET_KEY` must belong to a funded testnet account. The deployer key works
because it was funded by Friendbot during `deploy_testnet.sh`.

## Exit codes

- `0` — `init()` committed on-chain
- `1` — submit or simulation failed (real error)
- `2` — already initialized (safe to ignore; the contract is already set up)

## Once the CLI bug is fixed

Delete this directory and use:

```bash
stellar contract invoke --id $BLEND_YIELD_POLICY \
  --source-account accesly-deployer --network testnet \
  -- init --accesly_wallet $ACCESLY_DEPLOYER
```
