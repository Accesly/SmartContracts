# Threat Model — Accesly Recovery (ZK email, rotación completa)

**Estado:** propuesta para audit.
**Owner:** Daniel Bustamante (Accesly Core).
**Alcance:** flow de recovery de Smart Account vía ZK email, implementado en
`zk-email-verifier v2` + `sep30Handler` Lambda + SDK `auth.recover()`.

## 1. Modelo

### 1.1 Asunciones

| Cubre | No cubre |
|---|---|
| Atacante con DKIM público de Google (o cualquier IdP DKIM trusted) | Atacante con custody del mailbox del usuario (recovery email comprometido) |
| Atacante que controla el HTTPS endpoint del CDN | Atacante con quorum del trusted setup ceremony |
| Atacante con cuenta IAM del backend (lee user_fragments) | Compromiso del DKIM private key de Google |
| Replay de proof entre wallets | Side-channel del browser (timing del prover) |

El threat model **asume** que la ceremony BLS12-381 cierra correctamente
(sin toxic-waste leak). Antes de mainnet hay que correr ceremony con 3-5
contributors externos del ecosistema Stellar — el `ceremony stub` actual
es solo para testnet.

### 1.2 Confidencialidad

| Dato | Quién lo ve en plano | Quién lo ve cifrado |
|---|---|---|
| Email del usuario | El usuario, su MTA, Google | Backend (sólo `sha256(email)` para command_hash, vía circuit) |
| Master key (v1) | El usuario | Nadie (Shamir 2-de-3, F1 local, F2/F3 en backend cifrados) |
| Master key (v2, post-recovery) | El usuario nuevo device | Igual |
| Passkey privada | El secure enclave del device | Nadie |
| ZK proof | Cualquiera (es pública por diseño Groth16) | — |
| Recovery command (subject del email) | El usuario, Google, posible relay MTA | Backend (sólo `command_hash` en signals) |

**Punto crítico:** el subject del email contiene la `new_passkey_pubkey` en
hex. Cualquiera con read access al mailbox (Google, snooping del MTA) puede
ver qué passkey el usuario quiere instalar, **pero no puede usarla** — solo
el dueño del private key del passkey puede firmar después con esa pubkey.

### 1.3 Integridad

| Asset | Mecanismo |
|---|---|
| Master key reconstruida | F1 (local) + F2 (cifrado en backend con derivación del passkey + email) + F3 (cifrado en backend con PBKDF2 del email). El backend NUNCA reconstruye, solo entrega ciphertexts. |
| Identidad del firmante del email | DKIM signature de Google validado client-side por el circuit. El `dkim_public_key_hash` (signals 2+3) tiene que coincidir con un par `(domain_hash, pk_hash)` registrado en el `DkimRegistry` del verifier. |
| Binding email ↔ wallet | `recipient_email_hash` (signals 0+1) tiene que coincidir con el `email_commitment` almacenado en el Smart Account al deploy. El verifier on-chain rechaza si difieren. |
| Binding proof ↔ new_passkey | `command_hash` (signals 6+7) tiene que coincidir con `sha256("Accesly Recovery: <wallet> -> <new_passkey>")`. La proof queda atada a exactamente esa transición. |
| Anti-replay | `email_nullifier` (signals 4+5) único por proof. El verifier persiste el set en `StorageKey::Nullifier(BytesN<32>)` y rechaza repetidos. |

## 2. Almanax BL-01 (CRITICAL) — mitigación

**Hallazgo original (2026-04-27):** `verify()` aceptaba cualquier proof si el
DKIM key estaba registrado, sin binding a `key_data` ni a `signature_payload`.
Atacante que tuviera un email DKIM-firmado por Google con CUALQUIER subject
podía pasar la auth recovery de **cualquier wallet**.

**Mitigación implementada en `verifier v2`:**

1. `public_signals.len() == 14` (rejection plana de proofs malformadas).
2. `recipient_email_hash` (signals 0+1) **==** `key_data` del Verifier trait
   (`email_commitment` del SA). Ata la proof al email del dueño legítimo.
3. `(domain_hash, dkim_pk_hash)` **registrado** y **no revocado** en el
   `DkimRegistry`. Sin esto, un atacante que comprometiera CUALQUIER DKIM
   key podría firmarse a sí mismo.
4. `command_hash` (signals 6+7) **==** `sha256(recovery_command)` donde
   `recovery_command` viene de la propia proof. El subject del email del
   usuario tiene que ser exactamente esa string, que contiene `wallet
   address` + `new_passkey_pubkey_hex`. Eso vincula la proof a la
   transición específica `(wallet, new_passkey)`.
5. `email_nullifier` (signals 4+5) único — burn-on-success, replay
   imposible cross-tx.
6. Pairing-check Groth16 BLS12-381 al final (cheap-fail-first orden).

Test de regresión `verify_rejects_email_commitment_mismatch` +
`verify_rejects_command_hash_mismatch` + `verify_rejects_unregistered_dkim`
+ `verify_rejects_revoked_dkim` + `verify_rejects_wrong_signal_count` en
`contracts/zk-email-verifier/src/contract/tests.rs`.

## 3. Flow E2E (rotación completa)

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Usuario abre la app en un device nuevo                       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. Usuario ingresa: email + wallet address                       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. SDK genera new passkey (secp256r1) + new master key (ed25519)│
│    + nuevo Shamir split F1'/F2'/F3'                              │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. SDK guía al usuario a enviar un email con subject:            │
│      "Accesly Recovery: <wallet> -> <new_passkey_hex>"           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. Usuario descarga el .eml en Gmail "Show original"             │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 6. SDK (@accesly/zkemail) descarga wasm + zkey del CDN,          │
│    genera Groth16 proof BLS12-381 client-side                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 7. SDK query a Soroban RPC: get_context_rules del SA →           │
│    descubre IDs de admin-cfg, sep10-auth, todas biometric-tx     │
│    + signer_ids de los owner_ed25519 viejos + secp256r1 viejo   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 8. SDK construye envelope con N operations atómicas:             │
│      - admin-cfg: remove(old_owner), add(new_owner_ed25519)      │
│      - sep10-auth: remove(old_secp), add(new_passkey)            │
│      - cada biometric-tx: remove(old_owner), add(new_owner)      │
│    AuthPayload: signer = zk_email_verifier, context_rule_ids =   │
│    [zk_recovery], signatures = [XDR-encoded ZkEmailProof v2]     │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 9. SDK encrypta F2' con derivación new passkey, F3' con PBKDF2  │
│    del email                                                     │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 10. SDK POST /sep30/accounts/{address}/recover con:              │
│       unsignedXdr, newSecp256r1Pubkey, newF2, newF3,             │
│       newEmailCommitment (= old, no cambia)                      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 11. Backend simulateAssembleAndSubmit:                           │
│       - Soroban simula la tx                                     │
│       - __check_auth evalúa zk-recovery rule                     │
│       - Llama verifier.verify(payload, email_commitment, proof)  │
│       - Si verify() == true: ejecuta add/remove signers          │
│       - Si verify() == false: tx falla, no muta estado           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 12. Backend recibe txHash. Persiste:                             │
│       user_fragments: nuevo secp256r1_pubkey + wrapped F2'       │
│       email_fragments: nuevo F3' (overwrite bajo mismo commit)   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 13. SDK guarda F1' en DeviceStore local. Wallet operativa.       │
└─────────────────────────────────────────────────────────────────┘
```

## 4. Ataques considerados

### 4.1 Atacante con email comprometido pero sin device

- **Asunción rota:** atacante tiene read+write access al recovery email.
- **Resultado:** atacante puede enviar el email de recovery con su propio
  new_passkey_pubkey, descargar el .eml, generar la proof, llamar al
  endpoint, y tomar control del wallet.
- **Mitigación product-level:** el `email_commitment` del SA es del email
  específico que el usuario usó al onboarding. Si ese email se compromete,
  el modelo no-custodial colapsa. Esto es **inherente al diseño SEP-30**
  y se asume aceptado en el threat model superior del producto.
- **Mitigación parcial:** habilitar 2FA en el email + monitor del nullifier
  registry off-chain — si aparece un nullifier inesperado, alertar al
  usuario via canal alternativo (push, SMS).

### 4.2 Atacante con DKIM private key de Google comprometida

- **Asunción rota:** Google's DKIM private key se exfiltra.
- **Resultado:** atacante puede DKIM-firmarse a sí mismo cualquier email,
  pasar el binding del registry, y tomar cualquier wallet con email Gmail.
- **Mitigación:** el `DkimRegistry` permite `revoke_dkim_public_key_hash`.
  Si Google publica un incident, admin revoca + rotación coordinada.
  Window de exposición: hasta el incident notice → revoke tx mined.

### 4.3 Replay de proof entre wallets

- **Vector:** atacante captura una proof válida emitida por el dueño
  legítimo de wallet A. Intenta usarla contra wallet B.
- **Bloqueado por:** binding (2) recipient_email_hash == key_data. El SA
  de wallet B tiene su propio email_commitment ≠ del SA de wallet A. La
  proof contiene el hash del email asociado a A, así que verify falla en
  wallet B.

### 4.4 Replay de proof en la misma wallet (con diferente new_passkey)

- **Vector:** atacante captura proof + reusa con un new_passkey distinto
  del que firmó el dueño.
- **Bloqueado por:** binding (4) command_hash == sha256(recovery_command).
  El subject del email tiene el new_passkey específico que el dueño
  ESCRIBIÓ. Sin cambiarlo (lo que implica firmar otro email DKIM, lo que
  implica tener access al email), command_hash no matchea.

### 4.5 Replay de la misma proof en la misma wallet (atacante intenta double-rotate)

- **Bloqueado por:** binding (5) email_nullifier único + persistente. Una
  proof se quema al primer uso exitoso.

### 4.6 Atacante con KMS Sign del backend

- **Vector:** atacante con acceso al KMS key del channels-fund firma una
  tx submitiendo CUALQUIER envelope al SA.
- **Bloqueado por:** la fee-bump signature solo paga gas. La auth real
  del SA pasa por `__check_auth` → context rule → verifier.verify(). El
  KMS del backend no firma como dueño del SA.

### 4.7 Atacante con read del `user_fragments` table

- **Vector:** atacante con IAM read access a DynamoDB lee F2 ciphertexts.
- **Bloqueado por:** F2 está cifrado client-side con derivación del
  passkey. Sin la passkey privada (en el secure enclave del device del
  usuario), F2 ciphertext es opaco. Backend solo añade un KMS rest-wrap
  encima — no aporta entropy nueva, pero protege contra dump de la tabla
  cruda en disco.

## 5. Operacional

### 5.1 Migración v1 → v2

- Wallets **v1** (deployados antes del deploy del verifier v2) referencian
  al verifier stub (`CDXR...DARH`) que retorna `false` siempre. Recovery
  **no funciona** en estos wallets — necesitan migración manual o
  re-onboarding.
- Wallets **v2** (deployados después) usan el verifier v2 real con la VK
  del ceremony BLS12-381. Recovery funciona end-to-end.
- No hay upgrade in-place del verifier address per-wallet — el constructor
  lo congela. Aceptado como deuda hasta tener un mecanismo de
  `set_zk_verifier(new_addr)` gated por admin-cfg (Phase 7).

### 5.2 Rotación del DKIM key de Google

- Google rota su DKIM key cada ~6 meses sin aviso público. Operacional:
  Lambda cron lee el DNS TXT de gmail.com cada hora, compara contra el
  registry on-chain, alerta si hay un par nuevo.
- Nuevos pares se registran vía Timelock 48h (D5 opción D, pendiente).
- Pares viejos quedan válidos durante una ventana de 12 meses post primera
  vista (programmed expiry, pendiente — Fase 7).

### 5.3 Métricas críticas

- Tasa de `recovery_completed` exitosos / fallidos por hora.
- Cantidad de nullifiers burned (debe coincidir con `recovery_completed`).
- Latencia del flow E2E (target P95 < 3 min incluyendo proof gen ~30-60s).
- Failed `verify()` calls on-chain (puede indicar attack attempt o bug).

## 6. Pendientes pre-mainnet

- [ ] Trusted setup ceremony con 3-5 contributors externos.
- [ ] Audit externo del verifier + Smart Account integration (Veridise / Zellic).
- [ ] Implementar Timelock 48h para `set_dkim_public_key_hash` (D5).
- [ ] Implementar programmed expiry para DKIM keys viejas (D5).
- [ ] Endpoint público `GET /sep30/accounts/by-email/{hash}` para que el
      usuario no tenga que recordar la wallet address (opcional, mejora UX).
- [ ] Bug bounty + responsible disclosure docs.
- [ ] Monitoring + alerting del nullifier registry (catch attack attempts).

## 7. Referencias

- Almanax BL-01 finding (2026-04-27): `docs/Vulnerabilidades SmartContracts.md`
- D1 Public signals decision: `accesly-zkemail/docs/Design_Decisions.md`
- D5 DKIM rotation policy: `accesly-zkemail/docs/Design_Decisions.md`
- SEP-30 spec: https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0030.md
- Groth16 paper: https://eprint.iacr.org/2016/260
- BLS12-381 in Soroban: https://developers.stellar.org/docs/learn/encyclopedia/contract-development/types/bls12-381
