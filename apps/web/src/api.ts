import type { Agent, AgentRun, Message, SafetyEvent, SystemInfo } from "./types";

export interface ApiErrorDetail {
  field: string;
  message: string;
}

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly details: ApiErrorDetail[] = [],
  ) {
    super(message);
  }
}

let authToken = "";

export function setAuthToken(token: string): void {
  authToken = token.trim();
}

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const headers = {
    ...(options?.body ? { "Content-Type": "application/json" } : {}),
    ...(authToken ? { Authorization: "Bearer " + authToken } : {}),
    ...options?.headers,
  };
  const response = await fetch(url, {
    ...options,
    headers,
  });
  const data = (await response.json().catch(() => ({}))) as T & {
    error?: string;
    details?: ApiErrorDetail[];
  };
  if (!response.ok) {
    throw new ApiError(
      data.error ?? "Request failed",
      response.status,
      data.details ?? [],
    );
  }
  return data;
}

export function getUserFacingError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.details.length > 0) {
      return error.details
        .map(({ field, message }) => 
          `${field.charAt(0).toUpperCase()}${field.slice(1)} -- ${message}`,
        )
        .join("; ");
    }
    return error.message;
  }

  return error instanceof Error ? error.message : String(error);
}

export const api = {
  auth: () => request<{ required: boolean }>("/api/auth"),
  system: () => request<SystemInfo>("/api/system"),
  listAgents: () => request<{ agents: Agent[] }>("/api/agents"),
  createAgent: (body: {
    name: string;
    description: string;
    instructions: string;
  }) =>
    request<{ agent: Agent }>("/api/agents", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateAgent: (
    id: string,
    body: { name: string; description: string; instructions: string },
  ) =>
    request<{ agent: Agent }>("/api/agents/" + id, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteAgent: (id: string) =>
    request<{ archivedWorkspace: string }>("/api/agents/" + id, {
      method: "DELETE",
    }),
  startAgent: (id: string) =>
    request<{ agent: Agent }>("/api/agents/" + id + "/start", {
      method: "POST",
    }),
  stopAgent: (id: string) =>
    request<{ agent: Agent }>("/api/agents/" + id + "/stop", {
      method: "POST",
    }),
  messages: (id: string) =>
    request<{ messages: Message[] }>("/api/agents/" + id + "/messages"),
  runs: (id: string) =>
    request<{ runs: AgentRun[] }>("/api/agents/" + id + "/runs"),
  sendMessage: (
    id: string,
    content: string,
    secrets: Record<string, string> = {},
  ) =>
    request<{ run: AgentRun; message: Message }>(
      "/api/agents/" + id + "/messages",
      {
        method: "POST",
        body: JSON.stringify({
          content,
          ...(Object.keys(secrets).length > 0 ? { secrets } : {}),
        }),
      },
    ),
  run: (id: string) => request<{ run: AgentRun }>("/api/runs/" + id),
  safetyEvents: (id: string) =>
    request<{ events: SafetyEvent[] }>("/api/runs/" + id + "/safety-events"),
};
