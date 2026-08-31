# Safety Middleware Hackathon Submission

This document is the repository handoff and the runbook for the three-minute
live demo. All values in examples are deliberately fake. Do not enter real
credentials into a demo prompt, a recording, or a commit.

## 1. Problem and rationale

An Agent platform creates a security visibility gap: a user prompt can reach an
LLM and a code-execution runtime before anyone can see whether it contained a
credential, personal data, a prompt-injection attempt, or an unsafe execution
outcome. A plain chat UI also makes these decisions invisible to the user.

This project adds an end-to-end safety middleware boundary. It detects and
redacts sensitive content, blocks high-risk prompt injection, keeps inline
values out of persisted traces and LLM input, records execution-boundary
decisions, and displays the result on a safety dashboard.

The goal is not to claim production compliance. The goal is to make an actual
Agent Run safer and its decisions inspectable.

## 2. Setup

### Requirements

- Node.js 22+ and npm 10+
- Docker, Colima, or Podman
- A Volcengine Ark Responses-compatible endpoint

### Start the real end-to-end POC

Set credentials in your shell or local `.env`; never show their values in the
recording:

```bash
cd /path/to/TeamTree
ARK_API_KEY=your-ark-api-key ARK_MODEL=ep-your-endpoint-id npm run poc
```

Open <http://localhost:3000>. Keep the terminal running. 

## 3. Design summary

```mermaid
flowchart LR
  U[User prompt] --> A[Fastify API]
  A --> S[AgentService + SafetyMiddleware]
  S -->|safe trace| D[(JSON store: runs, messages, events)]
  S -->|opaque inline placeholders| R[CodexRunner / ContainerCodexRunner]
  V[Run Values] -->|temporary environment variables| R
  R -->|ALLOW / BLOCK / CANCELLED| S
  S --> E[Safety event timeline]
  E --> UI[Safety dashboard]
```

### Main decisions

- **API / Service:** provider-secret, generic credential, PII, and
  prompt-injection rules are evaluated before a Runner is started.
- **Vault-backed inline protection:** inline matched values become
  `[REDACTED_SECRET]` or `[REDACTED_PII]` in persistence and an opaque
  `[PRIVATE_…]` placeholder in the LLM execution prompt.
- **Offline confidence score:** generic credential assignments use Shannon
  entropy plus a local logistic-regression score. UUIDs, Git SHA values, and
  ordinary Base64 are suppressed to reduce false positives.
- **Runner boundary:** both local and container runners emit start, timeout,
  cancellation, and output-limit decisions.
- **Dashboard:** the UI polls real run and safety-event data, showing status,
  decision, boundary, reason, and timestamp. It does not display original
  secrets.

## 4. Automated evidence

Run these before recording:

```bash
npm run typecheck
npm run test
npm run build -w @launchpad/web
```

Relevant automated coverage includes:

- known secret and PII redaction;
- prompt-injection blocking;
- Vault placeholder and in-memory restoration behavior;
- classifier suppression for UUID, Git SHA, and ordinary Base64;
- UUID-versus-phone-number false-positive regression;
- AgentService persistence and Runner-input redaction;
- Runner success, timeout, user cancellation, failed process, and output-limit
  safety events.



## 5. Limitations and honest scope

- This is a single-user hackathon POC, not a production compliance product.
- Regexes, entropy, and a small local classifier reduce risk but cannot prove
  that arbitrary text is or is not sensitive.
- The classifier is local and offline; no external ML model is called at
  runtime. It is fast, but it is not continuously retrained.
- Run Values are a temporary runtime-variable channel. Their `Secret` and
  `Non-secret` UI classifications do not currently create different backend
  delivery policies; neither is a bypass for prompt safety.
- The dashboard is polling-based rather than a real-time streaming channel.
- Container controls reduce blast radius but do not replace production
  authentication, authorization, secret management, monitoring, or a formal
  incident-response program.



## 6. Related implementation files

- `apps/server/src/safety-middleware.ts` — rules, policy, redaction, Vault
  placeholder generation.
- `apps/server/src/secret-confidence.ts` — local logistic score.
- `apps/server/src/patterns/` — secret, PII/compliance, and injection rules.
- `apps/server/src/agent-service.ts` — persistence and safe Runner handoff.
- `apps/server/src/codex-runner.ts` and `container-codex-runner.ts` — Runner
  events and execution controls.
- `apps/web/src/components/SafetyStatus.tsx`, `SafetyEvents.tsx`, and
  `RunControls.tsx` — dashboard UI.
- `apps/server/src/*test.ts` — automated evidence.
