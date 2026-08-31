export type AgentStatus = "ready" | "busy" | "stopped" | "error";

export type RunStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled"
  | "blocked";

export type MessageRole = "user" | "assistant";

export type SafetyBoundary = "API" | "SERVICE" | "RUNNER";

export type SafetyDecision = "ALLOW" | "BLOCK" | "REDACT" | "CANCELLED";

export interface SafetyEvent {
  id: string;
  runId?: string;
  userId?: string;
  agentId?: string;
  boundary: SafetyBoundary;
  decision: SafetyDecision;
  reason: string;
  /** Safe rule metadata only; never includes prompt text or secret values. */
  metadata?: {
    findingIds?: string[];
    findingCategories?: string[];
    secretNames?: string[];
  };
  timestamp: string;
}

export interface Agent {
  id: string;
  name: string;
  description: string;
  instructions: string;
  status: AgentStatus;
  workspacePath: string;
  codexThreadId: string | null;
  lastError: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface Message {
  id: string;
  agentId: string;
  runId: string;
  role: MessageRole;
  content: string;
  createdAt: string;
}

export interface RunUsage {
  inputTokens?: number;
  cachedInputTokens?: number;
  outputTokens?: number;
}

export interface ToolCallBreakdown {
  commands: number;
  fileEdits: number;
  other: number;
}

export interface AgentRun {
  id: string;
  agentId: string;
  status: RunStatus;
  prompt: string;
  output: string | null;
  error: string | null;
  usage: RunUsage | null;
  stepCount: number | null;
  toolCalls: ToolCallBreakdown | null;
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
}

export interface Database {
  version: 1;
  agents: Agent[];
  messages: Message[];
  runs: AgentRun[];
  safetyEvents: SafetyEvent[];
}

export interface CreateAgentInput {
  name: string;
  description?: string | undefined;
  instructions?: string | undefined;
}

export interface UpdateAgentInput {
  name?: string | undefined;
  description?: string | undefined;
  instructions?: string | undefined;
}

export interface RunnerResult {
  output: string;
  threadId: string | null;
  usage: RunUsage | null;
  /**
   * Count of every completed Codex work item (reasoning, commands, file
   * changes, tool calls, the final message, etc). A coarse "how much did
   * the agent do" signal. Optional so runner implementations/mocks that
   * don't track this can omit it — AgentService falls back to null
   * ("not reported") in that case.
   */
  stepCount?: number;
  /**
   * Breakdown of real actions taken against the world during this run:
   * shell commands, file edits, and everything else (MCP tool calls, web
   * search). Excludes reasoning and the final agent_message — those aren't
   * "actions", so counting them wouldn't tell you anything useful. Optional
   * so runner implementations/mocks that don't track this can omit it —
   * AgentService falls back to null ("not reported") in that case.
   */
  toolCalls?: ToolCallBreakdown;
}

export interface RunnerSafetyEvent {
  decision: Extract<SafetyDecision, "ALLOW" | "BLOCK" | "CANCELLED">;
  reason: string;
}

export interface RunnerRequest {
  agentId: string;
  workspacePath: string;
  prompt: string;
  threadId: string | null;
  secrets?: Record<string, string>;
  onSafetyEvent?: (event: RunnerSafetyEvent) => Promise<void>;
}

export interface AgentRunner {
  run(request: RunnerRequest): Promise<RunnerResult>;
  cancel(agentId: string): Promise<boolean>;
  isAvailable(): Promise<boolean>;
}
