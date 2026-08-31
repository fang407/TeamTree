import { randomUUID } from "node:crypto";
import type { AppConfig } from "./config.js";
import { isArkConfigured } from "./config.js";
import { HttpError, RunCancelledError } from "./errors.js";
import { JsonStore } from "./store.js";
import type {
  Agent,
  AgentRun,
  AgentRunner,
  CreateAgentInput,
  LearnedSecretPatternRecord,
  Message,
  SafetyEvent,
  SecretSignatureRecord,
  UpdateAgentInput,
} from "./types.js";
import { WorkspaceManager } from "./workspace.js";
import { SafetyMiddleware, type SafetyCheckResult, type ComplianceFramework, learnedSecretPatternId } from "./safety-middleware.js";
import { extractSecretSignature } from "./utils/textUtils.js";

const now = () => new Date().toISOString();

function redactSecrets(
  text: string,
  secrets: Record<string, string>,
  allowPartial: boolean,
): string {
  return Object.values(secrets).reduce(
    (redacted, secret) => {
      if (!secret) return redacted;

      const replacement =
        allowPartial && secret.length > 6
          ? `[PARTIAL_SECRET:${secret.slice(0, 3)}…${secret.slice(-3)}]`
          : "[REDACTED_SECRET]";

      return redacted.split(secret).join(replacement);
    },
    text,
  );
}

export class AgentService {
  private readonly activeExecutions = new Map<string, Promise<void>>();
  private readonly cancellationRequests = new Set<string>();

  constructor(
    private readonly config: AppConfig,
    private readonly store: JsonStore,
    private readonly workspaces: WorkspaceManager,
    private readonly runner: AgentRunner,
    private readonly safetyMiddleware: SafetyMiddleware,
  ) {}

  async initialize(): Promise<void> {
    await this.store.initialize();
    await this.workspaces.initialize();
    await this.store.mutate((database) => {
      for (const run of database.runs) {
        if (run.status === "queued" || run.status === "running") {
          run.status = "cancelled";
          run.error = "Server restarted while this run was active";
          run.completedAt = now();
        }
      }
      for (const agent of database.agents) {
        if (agent.status === "busy") {
          agent.status = "ready";
          agent.updatedAt = now();
        }
      }
    });

    // Re-register patterns learned in a previous run — only the declared
    // name and a length bound are needed, nothing sensitive to rehydrate.
    for (const learned of this.store.snapshot().learnedSecretPatterns) {
      this.safetyMiddleware.learnSecretPattern(learned.name, learned.minValueLength);
    }
  }

  listAgents(): Agent[] {
    return this.store
      .snapshot()
      .agents.sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
  }

  getAgent(id: string): Agent {
    const agent = this.store.snapshot().agents.find((item) => item.id === id);
    if (!agent) {
      throw new HttpError(404, "Agent not found");
    }
    return agent;
  }

  async createAgent(input: CreateAgentInput): Promise<Agent> {
    const timestamp = now();
    const id = randomUUID();
    const agent: Agent = {
      id,
      name: input.name.trim(),
      description: input.description?.trim() ?? "",
      instructions: input.instructions?.trim() ?? "",
      status: "ready",
      workspacePath: this.workspaces.workspacePath(id),
      codexThreadId: null,
      lastError: null,
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    await this.workspaces.create(agent);
    await this.store.mutate((database) => database.agents.push(agent));
    return agent;
  }

  async updateAgent(id: string, input: UpdateAgentInput): Promise<Agent> {
    const current = this.getAgent(id);
    if (current.status === "busy") {
      throw new HttpError(409, "Stop the active run before editing this Agent");
    }
    const updated = await this.store.mutate((database) => {
      const agent = database.agents.find((item) => item.id === id);
      if (!agent) {
        throw new HttpError(404, "Agent not found");
      }
      if (agent.status === "busy") {
        throw new HttpError(409, "Stop the active run before editing this Agent");
      }
      if (input.name !== undefined) agent.name = input.name.trim();
      if (input.description !== undefined) agent.description = input.description.trim();
      if (input.instructions !== undefined) agent.instructions = input.instructions.trim();
      agent.lastError = null;
      agent.updatedAt = now();
      return structuredClone(agent);
    });
    await this.workspaces.writeInstructions(updated);
    return updated;
  }

  async deleteAgent(id: string): Promise<{ archivedWorkspace: string }> {
    const agent = this.getAgent(id);
    await this.cancelExecution(id);
    const archivedWorkspace = await this.workspaces.archive(agent);
    await this.store.mutate((database) => {
      database.agents = database.agents.filter((item) => item.id !== id);
      database.messages = database.messages.filter((item) => item.agentId !== id);
      database.runs = database.runs.filter((item) => item.agentId !== id);
    });
    return { archivedWorkspace };
  }

  async startAgent(id: string): Promise<Agent> {
    return this.setStatus(id, "ready");
  }

  async stopAgent(id: string): Promise<Agent> {
    this.getAgent(id);
    await this.cancelExecution(id);
    return this.setStatus(id, "stopped");
  }

  getMessages(agentId: string): Message[] {
    this.getAgent(agentId);
    return this.store
      .snapshot()
      .messages.filter((message) => message.agentId === agentId)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  getRun(runId: string): AgentRun {
    const run = this.store.snapshot().runs.find((item) => item.id === runId);
    if (!run) {
      throw new HttpError(404, "Run not found");
    }
    return run;
  }

  getRuns(agentId: string): AgentRun[] {
    this.getAgent(agentId);
    return this.store
      .snapshot()
      .runs.filter((run) => run.agentId === agentId)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  }

  getSafetyEvents(runId: string): SafetyEvent[] {
    this.getRun(runId);

    return this.store
      .snapshot()
      .safetyEvents.filter((event) => event.runId === runId)
      .sort((left, right) => left.timestamp.localeCompare(right.timestamp));
  }

  getSecretSignatures(): SecretSignatureRecord[] {
    return this.store
      .snapshot()
      .secretSignatures.sort((left, right) => right.occurrences - left.occurrences);
  }

  /**
   * Grows the secret-pattern collection from explicit, user-declared
   * secrets (the "Run secrets" panel) — never from free-text prompt
   * content. The person has already told us these are secrets, so unlike
   * inferring from a prompt, no confidence scoring or human audit gate is
   * needed for *this* source: only the structural shape is persisted
   * (length, entropy, character classes), never the value itself. Repeat
   * sightings of the same shape increment a counter instead of adding
   * duplicate rows, so this stays small regardless of how often the same
   * secret is reused across runs.
   */
  private async recordSecretSignatures(
    secrets: Record<string, string>,
  ): Promise<void> {
    const entries = Object.entries(secrets).filter(([, value]) => value.length > 0);
    if (entries.length === 0) return;

    const timestamp = now();

    await this.store.mutate((database) => {
      for (const [name, value] of entries) {
        const signature = extractSecretSignature(value);
        const existingSignature = database.secretSignatures.find(
          (record) =>
            record.length === signature.length &&
            record.entropy === signature.entropy &&
            record.hasUpper === signature.hasUpper &&
            record.hasLower === signature.hasLower &&
            record.hasDigit === signature.hasDigit &&
            record.hasSymbol === signature.hasSymbol,
        );

        if (existingSignature) {
          existingSignature.occurrences += 1;
          existingSignature.lastSeenAt = timestamp;
        } else {
          database.secretSignatures.push({
            id: randomUUID(),
            ...signature,
            occurrences: 1,
            firstSeenAt: timestamp,
            lastSeenAt: timestamp,
          });
        }

        // Auto-promote a detection rule keyed on the declared NAME (not
        // the value's characters) — see SafetyMiddleware.learnSecretPattern
        // for why this is safe to do without a human audit step.
        this.safetyMiddleware.learnSecretPattern(name, value.length);

        const learnedId = learnedSecretPatternId(name);
        const existingLearned = database.learnedSecretPatterns.find(
          (record) => record.id === learnedId,
        );

        if (existingLearned) {
          existingLearned.occurrences += 1;
          existingLearned.lastSeenAt = timestamp;
          existingLearned.minValueLength = Math.min(
            existingLearned.minValueLength,
            value.length,
          );
        } else {
          database.learnedSecretPatterns.push({
            id: learnedId,
            name,
            minValueLength: value.length,
            occurrences: 1,
            firstSeenAt: timestamp,
            lastSeenAt: timestamp,
          });
        }
      }
    });
  }

  getLearnedSecretPatterns(): LearnedSecretPatternRecord[] {
    return this.store
      .snapshot()
      .learnedSecretPatterns.sort((left, right) => right.occurrences - left.occurrences);
  }

  async sendMessage(
    agentId: string,
    prompt: string,
    secrets: Record<string, string> = {},
  ): Promise<{ run: AgentRun; message: Message }> {
    if (!isArkConfigured(this.config)) {
      throw new HttpError(
        503,
        "Ark is not configured. Set ARK_API_KEY and ARK_MODEL, then restart.",
      );
    }
    // Independent of prompt evaluation below — this only ever reads from
    // explicit, user-declared secrets, never from prompt text. Awaited
    // (not fire-and-forget) since it's a single cheap store mutation, the
    // same cost class as the "mark agent busy" mutation just below — but
    // guarded so a recording failure can never break the actual send.
    await this.recordSecretSignatures(secrets).catch(() => undefined);

    const timestamp = now();
    const runId = randomUUID();

    const safetyResult = await this.safetyMiddleware.evaluate(prompt);
    const storedPrompt = safetyResult.redactedPrompt;

    const run: AgentRun = {
      id: runId,
      agentId,
      status: "queued",
      prompt: storedPrompt,
      output: null,
      error: null,
      usage: null,
      stepCount: null,
      toolCalls: null,
      startedAt: null,
      completedAt: null,
      createdAt: timestamp,
    };
    const message: Message = {
      id: randomUUID(),
      agentId,
      runId,
      role: "user",
      content: storedPrompt,
      createdAt: timestamp,
    };
    const agentAtStart = await this.store.mutate((database) => {
      const storedAgent = database.agents.find((item) => item.id === agentId);
      if (!storedAgent) {
        throw new HttpError(404, "Agent not found");
      }
      if (storedAgent.status === "stopped") {
        throw new HttpError(409, "Start the Agent before sending a message");
      }
      if (storedAgent.status === "busy") {
        throw new HttpError(409, "This Agent is already running");
      }
      database.runs.push(run);
      database.messages.push(message);
      const snapshot = structuredClone(storedAgent);
      storedAgent.status = "busy";
      storedAgent.lastError = null;
      storedAgent.updatedAt = timestamp;
      return snapshot;
    });
    const execution = this.executeRun(
      agentAtStart,
      run,
      prompt,
      safetyResult,
      secrets,
    );
    this.activeExecutions.set(agentId, execution);
    void execution
      .finally(() => {
        if (this.activeExecutions.get(agentId) === execution) {
          this.activeExecutions.delete(agentId);
        }
      })
      .catch(() => undefined);
    return { run, message };
  }

  async systemInfo(): Promise<Record<string, unknown>> {
    return {
      arkConfigured: isArkConfigured(this.config),
      arkBaseUrl: this.config.arkBaseUrl,
      arkModel: this.config.arkModel || null,
      codexAvailable: await this.runner.isAvailable(),
      codexSandboxMode: this.config.codexSandboxMode,
      runtimeProvider: this.config.runtimeProvider,
      containerEngine:
        this.config.runtimeProvider === "container"
          ? this.config.containerEngine
          : null,
      runtime:
        this.config.runtimeProvider === "container"
          ? "Codex CLI in " + this.config.containerEngine + " Runtime"
          : "Codex CLI in application container",
    };
  }

  getRedactionConfig(): {
    redactionEnabled: boolean;
    complianceFrameworks: ComplianceFramework[];
    enabledPatternIds: string[];
    disabledPatternIds: string[];
    availablePatterns: {
      id: string;
      description: string;
      severity: string;
      frameworks: ComplianceFramework[];
    }[];
  } {
    const policy = this.safetyMiddleware.getConfig();
    return {
      redactionEnabled: policy.redactionEnabled,
      complianceFrameworks: policy.compliance.frameworks,
      enabledPatternIds: policy.compliance.enabledPatternIds,
      disabledPatternIds: policy.compliance.disabledPatternIds,
      availablePatterns: this.safetyMiddleware.listPiiPatterns(),
    };
  }

  updateRedactionConfig(update: {
    redactionEnabled?: boolean | undefined;
    complianceFrameworks?: ComplianceFramework[] | undefined;
    enabledPatternIds?: string[] | undefined;
    disabledPatternIds?: string[] | undefined;
  }): {
    redactionEnabled: boolean;
    complianceFrameworks: ComplianceFramework[];
    enabledPatternIds: string[];
    disabledPatternIds: string[];
    availablePatterns: {
      id: string;
      description: string;
      severity: string;
      frameworks: ComplianceFramework[];
    }[];
  } {
    const policy = this.safetyMiddleware.updateRedactionRules(update);
    return {
      redactionEnabled: policy.redactionEnabled,
      complianceFrameworks: policy.compliance.frameworks,
      enabledPatternIds: policy.compliance.enabledPatternIds,
      disabledPatternIds: policy.compliance.disabledPatternIds,
      availablePatterns: this.safetyMiddleware.listPiiPatterns(),
    };
  }

  private async executeRun(
    agentAtStart: Agent, 
    run: AgentRun,
    originalPrompt: string,
    safetyResult: SafetyCheckResult,
    secrets: Record<string, string>,
  ): Promise<void> {
    await this.store.mutate((database) => {
      const storedRun = database.runs.find((item) => item.id === run.id);
        if (storedRun) {
          storedRun.status = "running";
          storedRun.startedAt = now();
        }
      });

    try {
      // Cheap check (Set.has is O(1)): skip the rest of this run entirely
      // if a cancellation arrived while the "running" status update above
      // was in flight.
      if (this.cancellationRequests.has(agentAtStart.id)) {
        throw new RunCancelledError();
      }

      if (safetyResult.wasRedacted) {
        await this.recordSafetyEvent({
          runId: run.id,
          agentId: agentAtStart.id,
          boundary: "SERVICE",
          decision: "REDACT",
          reason: "Secret removed from trace",
        });
      }

      if (safetyResult.decision === "BLOCK") {
        const completedAt = now();

        await this.store.mutate((database) => {
          const storedRun = database.runs.find((item) => item.id === run.id);
          const agent = database.agents.find(
            (item) => item.id === agentAtStart.id,
          );

          if (storedRun) {
            storedRun.status = "blocked";
            storedRun.error = safetyResult.reason;
            storedRun.completedAt = completedAt;
          }

          if (agent) {
            agent.status = "ready";
            agent.lastError = null;
            agent.updatedAt = completedAt;
          }
        });

        await this.recordSafetyEvent({
          runId: run.id,
          agentId: agentAtStart.id,
          boundary: "SERVICE",
          decision: "BLOCK",
          reason: safetyResult.reason,
        });

        return;
      }

      await this.recordSafetyEvent({
        runId: run.id,
        agentId: agentAtStart.id,
        boundary: "SERVICE",
        decision: "ALLOW",
        reason: safetyResult.reason,
      });

      // Second cheap check, placed right before the expensive step
      // (spawning the actual Codex process, possibly in a container).
      // The awaits above (safety event writes) are a real window where a
      // cancellation could arrive — this is where skipping actually saves
      // meaningful cost, unlike re-checking immediately after the first
      // check with no work in between.
      if (this.cancellationRequests.has(agentAtStart.id)) {
        throw new RunCancelledError();
      }

      const result = await this.runner.run({
        agentId: agentAtStart.id,
        workspacePath: agentAtStart.workspacePath,
        // The LLM receives opaque placeholders for inline values. Secrets
        // intentionally supplied through the UI travel separately as Runner
        // environment variables and are never interpolated into this prompt.
        prompt: safetyResult.executionPrompt,
        threadId: agentAtStart.codexThreadId,
        secrets,
        onSafetyEvent: (event) =>
          this.recordSafetyEvent({
            runId: run.id,
            agentId: agentAtStart.id,
            boundary: "RUNNER",
            decision: event.decision,
            reason: event.reason,
          }),
      });

      const completedAt = now();

      const safeOutput = redactSecrets(
        this.safetyMiddleware.redactText(result.output),
        secrets,
        this.config.allowPartialSecretRedaction,
      );

      await this.store.mutate((database) => {
        const storedRun = database.runs.find((item) => item.id === run.id);
        const agent = database.agents.find((item) => item.id === agentAtStart.id);
        if (!storedRun || !agent) return;

        storedRun.status = "completed";
        storedRun.output = safeOutput;
        storedRun.usage = result.usage;
        storedRun.stepCount = result.stepCount ?? null;
        storedRun.toolCalls = result.toolCalls ?? null;
        storedRun.completedAt = completedAt;
        database.messages.push({
          id: randomUUID(),
          agentId: agent.id,
          runId: run.id,
          role: "assistant",
          content: safeOutput,
          createdAt: completedAt,
        });
        agent.status = "ready";
        agent.codexThreadId = result.threadId;
        agent.lastError = null;
        agent.updatedAt = completedAt;
      });

      await this.recordSafetyEvent({
        runId: run.id,
        agentId: agentAtStart.id,
        boundary: "SERVICE",
        decision: "ALLOW",
        reason: "Run completed",
      });
    } catch (error) {
      const completedAt = now();
      const cancelled = error instanceof RunCancelledError;
      const message = error instanceof Error ? error.message : String(error);
      const safeMessage = redactSecrets(
        this.safetyMiddleware.redactText(message),
        secrets,
        this.config.allowPartialSecretRedaction,
      );
      await this.store.mutate((database) => {
        const storedRun = database.runs.find((item) => item.id === run.id);
        const agent = database.agents.find((item) => item.id === agentAtStart.id);
        if (storedRun) {
          storedRun.status = cancelled ? "cancelled" : "failed";
          storedRun.error = safeMessage;
          storedRun.completedAt = completedAt;
        }
        if (agent) {
          if (agent.status !== "stopped") {
            agent.status = cancelled ? "ready" : "error";
          }
          agent.lastError = cancelled ? null : safeMessage;
          agent.updatedAt = completedAt;
        }
      });

      await this.recordSafetyEvent({
        runId: run.id,
        agentId: agentAtStart.id,
        boundary: "SERVICE",
        decision: cancelled ? "CANCELLED" : "ALLOW",
        reason: cancelled ? "Run cancelled" : "Run failed",
      });
    } finally {
      for (const key of Object.keys(secrets)) {
        delete secrets[key];
      }
    }
  }

  private async setStatus(id: string, status: Agent["status"]): Promise<Agent> {
    return this.store.mutate((database) => {
      const agent = database.agents.find((item) => item.id === id);
      if (!agent) {
        throw new HttpError(404, "Agent not found");
      }
      if (status === "ready" && agent.status === "busy") {
        throw new HttpError(409, "Stop the active run before starting this Agent");
      }
      agent.status = status;
      if (status === "ready") agent.lastError = null;
      agent.updatedAt = now();
      return structuredClone(agent);
    });
  }

  private async cancelExecution(agentId: string): Promise<void> {
    this.cancellationRequests.add(agentId);
    try {
      await this.runner.cancel(agentId);
      const execution = this.activeExecutions.get(agentId);
      if (execution) {
        await execution;
      }
    } finally {
      this.cancellationRequests.delete(agentId);
    }
  }

  private async recordSafetyEvent(
    event: Omit<SafetyEvent, "id" | "timestamp">,
  ): Promise<void> {
    await this.store.mutate((database) => {
      database.safetyEvents.push({
        ...event,
        id: randomUUID(),
        timestamp: now(),
      });
    });
  }
}
