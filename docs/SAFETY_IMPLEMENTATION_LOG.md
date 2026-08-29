# Safety Implementation Log

This file records code changes made for the hackathon safety middleware. It
contains architecture and verification information only; it must never contain
raw prompts, credentials, vault mappings, or CredData samples.

## 2026-08-29 - Vault-backed redaction and local classifier

### Added `apps/server/src/safety-middleware.ts`

- Added `SafetyVault`, a per-run in-memory mapping between sensitive values
  and opaque `[PRIVATE_<TYPE>_<UUID>]` placeholders.
- Added recursive redaction for strings, arrays, and plain objects. Sensitive
  field names and text detectors emit value-free `RedactionFinding` metadata.
- Added `restoreText()` for the trusted server-side response path. Vaults must
  not be serialized, logged, or persisted unencrypted.
- Added `checkExecutionPrompt()` and dangerous-execution rules for recursive
  filesystem deletion and downloaded content piped to a shell.
- Added Shannon-entropy features and `minConfidence` for unknown candidate
  strings.

### Added `apps/server/scripts/train-secret-confidence.py`

- Added a standalone, standard-library-only CredData training script.
- The script extracts labelled value spans, creates the same runtime feature
  vector, trains a class-balanced logistic-regression model, and emits only
  aggregate metrics and numeric weights.
- The script does not print, export, or write any training credential values.

### Updated classifier parameters

- Embedded `TRAINED_SECRET_LOGIT_MODEL` in `safety-middleware.ts` from a
  CredData partial-checkout run: 11,423 training spans and 2,851 validation
  spans.
- Recorded validation metrics: precision 0.9346, recall 0.7566, F1 0.8363.
- Applied product guardrails over the raw model output: UUIDs and Git-like
  hex digests score zero; uncontextualized Base64 values are down-weighted.

### Added `apps/server/src/safety-middleware.test.ts`

- Tests vault placeholder creation and trusted restoration.
- Tests confidence handling for UUID, Git SHA, Base64, and a known token
  prefix.
- Tests configurable `minConfidence` behavior.

### Verification

- Ran `npm run typecheck` successfully.
- Ran `npm run test` successfully: 6 test files and 15 tests passed.

## 2026-08-29 - Prototype branch restoration

### Restored

- Restored the vault-backed redaction prototype, its tests, and its offline
  training script from the saved Git stash into the `member3-redaction`
  branch.

### Compatibility note

- The restored prototype intentionally retains its original API. The current
  main-branch `AgentService` expects a separate `SafetyMiddleware.evaluate()`
  adapter, so full-repository type checking is deferred until that integration
  work is explicitly approved.
