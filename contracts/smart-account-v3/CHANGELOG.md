# accesly-smart-account-v3 — CHANGELOG

## 0.2.0 — 2026-07-03 (Fase T)

### Fix
- **`rotate_signer` fallaba con `txSorobanInvalid` en wallets con 4+ context rules.**
  El rotate atómico escribía ~166KB en el footprint (medido en wallet con
  admin-cfg + sep10-auth + 2× biometric-tx), sobrepasando el cap P27 de
  `txWriteBytes` (132KB). Todos los usuarios que activaron USDC y XLM
  quedaban sin poder ejecutar recovery.

### Added
- **`rotate_signer_partial(rule_ids: Vec<u32>, new_owner_ed25519, new_secp256r1_pubkey)`**
  Rota solo el subset de rules pasadas. Diseñada para llamarse N veces
  batcheando rules hasta cubrir todas las que tienen el signer viejo. No
  toca `email_commitment`, no emite `SignerRotated`. Auth por `admin-cfg`.

- **`finalize_rotation(new_owner_ed25519, new_secp256r1_pubkey, new_email_commitment)`**
  Cierra el flow multi-tx: persiste `email_commitment` en storage y emite
  `SignerRotated` con el set completo de nuevos identificadores. Auth por
  `admin-cfg` firmada por el **nuevo** owner (safety net: si el batch no se
  completó, la nueva firma no valida y el finalize falla).

- Nuevos códigos de error:
  - `EmptyRuleIdsInPartial = 9102`
  - `RuleIdOutOfRange = 9103`
  - `RuleNotRotatable = 9104`

### Backward compatibility
- `rotate_signer(new_owner, new_secp, new_email_commitment)` legacy intacto.
  Sigue funcionando en wallets con ≤ 3 rules donde el rotate atómico cabe
  bajo el cap. WASM hash cambia, pero la ABI existente no rompe.

### SDK / Lambda changes required
- Backend `assembleAndSubmitTransfer` ahora chequea `writeBytes` post-resim
  y devuelve `SorobanWriteCapExceededError` en lugar de dejar que el submit
  bounce con `txSorobanInvalid` opaco. Ver
  `CloudServices-accesly/lambdas/shared/src/soroban-transfer.ts`.
- Lambda `recovery-otp/finalize` mapea a HTTP 422 con `code:
  ROTATE_SIGNER_WRITE_CAP_EXCEEDED` para que el SDK dispare el flow de
  upgrade a v3.2.0 antes de reintentar el recovery.
- SDK `@accesly/react` v1.19+ agregará el flow multi-tx que llama
  `rotate_signer_partial` en batches y termina con `finalize_rotation`.

### Rollout plan
1. Upload WASM v3.2.0 a testnet → registrar en DDB `contract-versions`
   con `status: uploaded`.
2. Test manual con 1-2 wallets dev. Confirmar rotate particionado
   funciona bajo cap.
3. Marcar `status: canary`. Cambiar `appConfig.wallet.targetVersion` en
   `app_d_prueba1_j42h0` (app de prueba) a `v3.2.0` con
   `rolloutStrategy: auto-propose`, `rolloutCohort: canary`.
4. Monitorear `GET /contracts` counts. Cuando >90% del canary migrado sin
   incidentes, marcar `stable`.
5. Extender `targetVersion` a apps productivos uno por uno.

---

## 0.1.0 — 2026-06-25 (Fase R)

Initial release. Constructor + bootstrap split para caber bajo el cap P27
(el constructor v3.0.0 excedía por `setup_context_rules` invocando
`batch_canonicalize_key` en las WASMs de los verifiers).

- `__constructor(deployer)` — solo guarda deployer autorizado.
- `bootstrap(...)` — instala rules + persiste storage.
- `rotate_signer(...)` — rota owner ed25519 + secp256r1 + email_commitment
  atómicamente (funciona en wallets con ≤ 3 rules).
- `upgrade(new_wasm_hash, operator)` — vía trait `Upgradeable` de OZ,
  auth por admin-cfg.
