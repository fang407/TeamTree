# Member 3 Implementation Log

This log records each Member 3 code edit. It contains only implementation and
verification metadata; it must not contain prompts, credentials, command
arguments, or agent output.

## 2026-08-29 - Runner event contract and API

### Edited

- `apps/server/src/types.ts`
- `apps/server/src/agent-service.ts`
- `apps/server/src/app.ts`

### Change

- Added an optional `onSafetyEvent` callback to `RunnerRequest` so existing
  Runner architecture can report lifecycle decisions without accessing the
  JSON store directly.
- Added a `RunnerSafetyEvent` contract restricted to `ALLOW`, `BLOCK`, and
  `CANCELLED` decisions.
- Connected Runner events to `AgentService.recordSafetyEvent()` with the
  current run and agent identifiers and the `RUNNER` boundary.
- Added `GET /api/runs/:id/safety-events` for the safety dashboard.

### Rationale

The Runner owns the execution decision; `AgentService` owns persistence. This
keeps both local-process and container runners consistent and avoids changing
their execution model.

## 2026-08-29 - Local and container Runner lifecycle events

### Edited

- `apps/server/src/codex-runner.ts`
- `apps/server/src/container-codex-runner.ts`

### Change

- Emit `RUNNER / ALLOW` after the execution process or container starts.
- Emit `RUNNER / CANCELLED` for timeout and user stop actions.
- Emit `RUNNER / BLOCK` once when the configured output limit is exceeded.
- Treat audit persistence as best-effort so an unavailable JSON store does not
  prevent process termination or container removal.

## 2026-08-29 - Test-suite unblock

### Edited

- `apps/server/src/agent-service.test.ts`

### Change

- Corrected an existing `aconst` typo to `const` so Vitest can parse the
  already-present AgentService safety test.

## 2026-08-29 - Safety dashboard components and client contract

### Edited

- `apps/web/src/types.ts`
- `apps/web/src/api.ts`
- `apps/web/src/styles.css`

### Added

- `apps/web/src/components/SafetyStatus.tsx`
- `apps/web/src/components/SafetyEvents.tsx`
- `apps/web/src/components/RunControls.tsx`

### Change

- Mirrored run and safety-event types needed by the dashboard.
- Added the client call for the Runner safety-event endpoint.
- Added a status badge, event timeline, and disabled-when-inactive Stop Run
  control. The timeline is designed for real events and has a neutral empty
  state instead of fabricated production data.

## 2026-08-29 - Dashboard integration and Run control

### Edited

- `apps/web/src/App.tsx`

### Change

- Fetch safety events with the selected run and on every active-run polling
  iteration, keeping the event timeline current beside run state.
- Added the safety status badge and timeline to the selected Agent view.
- Connected Stop Run to the existing Agent stop/cancellation path; the control
  is disabled unless the current run is queued or running.

## 2026-08-29 - Runner lifecycle verification

### Added

- `apps/server/src/runner-safety-events.test.ts`

### Change

- Added deterministic executable fixtures for local and container Runner
  paths, without requiring Codex, Docker, or Podman in test environments.
- Covered execution start, timeout, user cancellation, output-limit blocking,
  failed processes, and the container Runner event path.

## 2026-08-29 - Demo and architecture handoff

### Added

- `docs/MEMBER3_DEMO.md`

### Change

- Documented the Runner event flow, existing container protections, dashboard
  API, and a three-case normal / stopped / output-limit demo script.

## 2026-08-29 - Demo startup instructions

### Edited

- `docs/MEMBER3_DEMO.md`

### Change

- Added the actual end-to-end `npm run poc` command, required Ark environment
  variables, presentation URL, and the distinction between POC and frontend
  development startup modes.

## 2026-08-29 - Split safety workspace layout

### Edited

- `apps/web/src/App.tsx`
- `apps/web/src/styles.css`

### Change

- Reworked the selected Agent view into a chat column and a right-side safety
  column, following the supplied dashboard layout reference.
- The safety column shows only available live data: run status, Agent, start
  time, token usage, real event timeline, and Stop Run. It intentionally does
  not fabricate user identity or step-count fields that the backend does not
  provide.

## 2026-08-29 - Current Run details

### Edited

- `apps/web/src/App.tsx`
- `apps/web/src/styles.css`

### Change

- Added the current run identifier and a duration derived from the run's real
  start/completion timestamps; the duration refreshes once per second while a
  run is active.
- Added explicit `Not reported` fields for Steps and Tool calls because the
  current Runner contract does not publish those metrics. This avoids showing
  invented values in the safety dashboard.

## 2026-08-29 - Runner test stability

### Edited

- `apps/server/src/runner-safety-events.test.ts`

### Change

- Increased the default test fixture timeout to allow a Node process to start
  reliably in slower local environments.
- Kept the explicit timeout scenario fast with its own short timeout, so the
  test continues to verify cancellation without introducing slow test runs.
- Gave the output-limit fixture additional time to drain its intentionally
  large stream before evaluating the output-limit assertion.
