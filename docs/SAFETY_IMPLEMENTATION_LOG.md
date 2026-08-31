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

## 2026-08-30 - Main middleware integration

### Updated

- `apps/server/src/safety-middleware.ts`
- `apps/server/src/secret-confidence.ts`
- `apps/server/src/patterns/secretPatterns.ts`
- `apps/server/src/agent-service.ts`
- `apps/server/src/agent-service.test.ts`
- `apps/server/src/safety-middleware.test.ts`

### Change

- Kept the current main-branch provider, PII, and prompt-injection rules as
  the detection baseline.
- Added a transient `SafetyVault` path which replaces inline secret/PII spans
  with opaque placeholders before the Runner/LLM receives the prompt. The
  persisted trace remains the stable `[REDACTED_SECRET]` / `[REDACTED_PII]`
  representation.
- Added the offline CredData-derived logistic confidence calculation as a
  second gate for generic credential assignments. UUIDs, Git-like digests,
  and ordinary Base64 remain suppressed to reduce false positives.
- Extended generic API-key field recognition to names such as `ARK_API_KEY`.
- Preserved generic credential field names while replacing only their values,
  so the LLM can safely refer to the separately supplied environment variable.

### Safety boundary

- Vault mappings remain process-memory only and are not exposed through the
  API or event records. The existing explicit `secrets` mechanism remains the
  only supported way to supply a value to an execution environment.

### Verification

- `npm run typecheck` completed successfully.
- `npm run test` completed successfully: 7 test files and 105 tests passed.

## 2026-08-30 - UUID / phone-number false-positive fix

### Updated

- `apps/server/src/safety-middleware.ts`
- `apps/server/src/safety-middleware.test.ts`

### Change

- Excluded phone-number matches that overlap a complete UUID. This prevents a
  numeric UUID suffix from being partially redacted as PII while preserving
  normal phone-number detection outside UUIDs.
- Added a regression test for a UUID used as an API-key-like identifier.

## 2026-08-30 - Run-value classification UI

### Updated

- `apps/web/src/App.tsx`
- `apps/web/src/styles.css`

### Change

- Reframed the secret panel as `Run values`, with an explicit `Secret` or
  `Non-secret` classification per temporary environment variable.
- Both kinds continue to use the existing protected runtime-value API path;
  classification never bypasses middleware or inserts raw values into the
  prompt, trace, or event timeline.
- Added export/import of value names and classifications, while accepting the
  previous names-only manifest for compatibility.

### Verification

- `npm run typecheck` completed successfully.
- `npm run build -w @launchpad/web` completed successfully.

## 2026-08-31 - Hackathon demo and repository handoff

### Added / updated

- `docs/HACKATHON_DEMO.md`
- `README.md`

### Change

- Added a three-minute live-demo runbook with a real normal Agent Run, a
  prompt-injection denial case, and an optional fake-secret redaction case.
- Added repository setup, architecture, automated-evidence, limitations, and
  no-secrets guidance for judges and teammates.
- Corrected the README's outdated statement that the POC has no tracing or
  audit middleware.

## 2026-08-31 - README safety middleware overview

### Updated

- `README.md`

### Change

- Embedded a concise safety middleware overview in the repository homepage:
  problem, architecture, design decisions, verification commands, scope, and
  no-secrets policy.
- Deliberately excluded the time-coded demo script and copy/paste prompts;
  those remain in `docs/HACKATHON_DEMO.md`.
