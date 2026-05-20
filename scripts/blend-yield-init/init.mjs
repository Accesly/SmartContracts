// Calls `blend-yield-policy.init(accesly_wallet)` on Stellar testnet.
//
// Why this script exists:
//   `stellar contract invoke` in CLI v26 fails with "Missing Entry Context" on
//   any OZ Policy contract that takes an Address arg. We bypass the CLI by
//   building the InvokeHostFunctionOp manually with @stellar/stellar-sdk.
//
// Required env vars:
//   POLICY_ADDRESS  — blend-yield-policy contract address (C...)
//   ACCESLY_WALLET  — canonical accesly wallet address (G... or C...)
//   SECRET_KEY      — secret key (S...) of the account that pays + signs
//
// Optional env vars:
//   RPC_URL         — soroban-rpc URL (default: https://soroban-testnet.stellar.org)
//   NETWORK         — "testnet" (default) or "mainnet"

import {
  Address,
  Contract,
  Networks,
  Operation,
  TransactionBuilder,
  Keypair,
  rpc,
  xdr,
} from "@stellar/stellar-sdk";

const must = (name) => {
  const v = process.env[name];
  if (!v) {
    console.error(`error: missing required env var ${name}`);
    process.exit(1);
  }
  return v;
};

const POLICY_ADDRESS = must("POLICY_ADDRESS");
const ACCESLY_WALLET = must("ACCESLY_WALLET");
const SECRET_KEY = must("SECRET_KEY");
const RPC_URL = process.env.RPC_URL ?? "https://soroban-testnet.stellar.org";
const NETWORK = process.env.NETWORK ?? "testnet";

const networkPassphrase =
  NETWORK === "mainnet" ? Networks.PUBLIC : Networks.TESTNET;

const server = new rpc.Server(RPC_URL, { allowHttp: RPC_URL.startsWith("http://") });
const signer = Keypair.fromSecret(SECRET_KEY);

console.log(`network:        ${NETWORK}`);
console.log(`rpc:            ${RPC_URL}`);
console.log(`signer:         ${signer.publicKey()}`);
console.log(`policy:         ${POLICY_ADDRESS}`);
console.log(`accesly_wallet: ${ACCESLY_WALLET}`);
console.log("");

const sourceAccount = await server.getAccount(signer.publicKey());

const contract = new Contract(POLICY_ADDRESS);
const acceslyAddrScVal = new Address(ACCESLY_WALLET).toScVal();

const op = contract.call("init", acceslyAddrScVal);

const tx = new TransactionBuilder(sourceAccount, {
  fee: "100000",
  networkPassphrase,
})
  .addOperation(op)
  .setTimeout(60)
  .build();

console.log("→ simulating transaction...");
const sim = await server.simulateTransaction(tx);

if (rpc.Api.isSimulationError(sim)) {
  console.error("simulation failed:", sim.error);
  // Most common cause: already initialized. The contract panics with
  // BlendYieldPolicyError::AlreadyInitialized (code 9001).
  if (typeof sim.error === "string" && sim.error.includes("9001")) {
    console.error("");
    console.error("→ The contract is ALREADY INITIALIZED. This is fine.");
    console.error("  Verify with: stellar contract invoke ... -- get_accesly_wallet");
    process.exit(2);
  }
  process.exit(1);
}

console.log("✓ simulation ok");
console.log("");

const prepared = await server.prepareTransaction(tx);
prepared.sign(signer);

console.log("→ submitting...");
const sendResult = await server.sendTransaction(prepared);
console.log(`status: ${sendResult.status}`);
console.log(`hash:   ${sendResult.hash}`);

if (sendResult.status === "ERROR") {
  console.error("send failed:", sendResult.errorResult);
  process.exit(1);
}

// Poll until the transaction lands.
let getResult;
for (let i = 0; i < 30; i++) {
  await new Promise((r) => setTimeout(r, 2000));
  getResult = await server.getTransaction(sendResult.hash);
  if (getResult.status !== "NOT_FOUND") break;
}

if (!getResult || getResult.status === "NOT_FOUND") {
  console.error("timed out waiting for transaction to land");
  process.exit(1);
}

console.log(`final status: ${getResult.status}`);
if (getResult.status === "SUCCESS") {
  console.log("");
  console.log("✓ blend-yield-policy.init() committed on-chain");
  console.log(`  Smart contract view: https://stellar.expert/explorer/${NETWORK}/contract/${POLICY_ADDRESS}`);
  process.exit(0);
}

console.error("transaction failed:", getResult);
process.exit(1);
