import { describe, expect, it } from "vitest";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import type { AgentService } from "./agent-service.js";

const service = {
  listAgents: () => [],
  systemInfo: async () => ({}),
  getSafetyEvents: () => [],
} as unknown as AgentService;

describe("HTTP boundary", () => {
  it("protects API routes with the configured shared token", async () => {
    const app = await createApp(
      loadConfig({ NODE_ENV: "test", APP_AUTH_TOKEN: "a-strong-test-token" }),
      service,
    );
    const denied = await app.inject({ method: "GET", url: "/api/agents" });
    expect(denied.statusCode).toBe(401);

    const allowed = await app.inject({
      method: "GET",
      url: "/api/agents",
      headers: { authorization: "Bearer a-strong-test-token" },
    });
    expect(allowed.statusCode).toBe(200);
    await app.close();
  });

  it("rejects an invalid bearer token", async () => {
    const app = await createApp(
      loadConfig({ NODE_ENV: "test", APP_AUTH_TOKEN: "a-strong-test-token" }),
      service,
    );

    const response = await app.inject({
      method: "GET",
      url: "/api/agents",
      headers: { authorization: "Bearer wrong-token" },
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({ error: "Authentication required" });
    await app.close();
  });

  it("rejects a non-Bearer authorization header", async () => {
    const app = await createApp(
      loadConfig({ NODE_ENV: "test", APP_AUTH_TOKEN: "a-strong-test-token" }),
      service,
    );

    const response = await app.inject({
      method: "GET",
      url: "/api/agents",
      headers: { authorization: "Basic credentials" },
    });

    expect(response.statusCode).toBe(401);
    await app.close();
  });

  it("preserves Fastify client error status codes", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);
    const malformed = await app.inject({
      method: "POST",
      url: "/api/agents",
      headers: { "content-type": "application/json" },
      payload: "{not-json",
    });
    expect(malformed.statusCode).toBe(400);

    const oversized = await app.inject({
      method: "POST",
      url: "/api/agents",
      headers: { "content-type": "application/json" },
      payload: JSON.stringify({ name: "x".repeat(1_100_000) }),
    });
    expect(oversized.statusCode).toBe(413);
    await app.close();
  });

  it("rejects an invalid agent UUID", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);

    const response = await app.inject({
      method: "GET",
      url: "/api/agents/not-a-uuid",
    });

    expect(response.statusCode).toBe(400);
    await app.close();
  });

  it("rejects a missing agent UUID", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);

    const response = await app.inject({
      method: "GET",
      url: "/api/agents/",
    });

    expect(response.statusCode).toBe(400);
    await app.close();
  })

  it("rejects an empty agent name", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);

    const response = await app.inject({
      method: "POST",
      url: "/api/agents",
      headers: { "content-type": "application/json" },
      payload: { name: "   " },
    });

    expect(response.statusCode).toBe(400);
    await app.close();
  });

  it("rejects a missing request body", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);

    const response = await app.inject({
      method: "POST",
      url: "/api/agents",
    });

    expect(response.statusCode).toBe(400);
    await app.close();
  });

  it("rejects empty message content", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);

    const response = await app.inject({
      method: "POST",
      url: "/api/agents/00000000-0000-0000-0000-000000000000/messages",
      headers: { "content-type": "application/json" },
      payload: { content: "\t  " },
    });

    expect(response.statusCode).toBe(400);
    await app.close();
  });

  it("rejects unknown request fields", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);

    const response = await app.inject({
      method: "POST",
      url: "/api/agents",
      headers: { "content-type": "application/json" },
      payload: { name: "demo", unexpected: true },
    });

    expect(response.statusCode).toBe(400);
    await app.close();
  });

  it("retrieves safety events for a valid run ID", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);

    const response = await app.inject({
      method: "GET",
      url: "/api/runs/00000000-0000-0000-0000-000000000000/safety-events",
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      events: [],
    });

    await app.close();
  });

  it("rejects an invalid safety-event run ID", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);

    const response = await app.inject({
      method: "GET",
      url: "/api/runs/not-a-uuid/safety-events",
    });

    expect(response.statusCode).toBe(400);
    await app.close();
  });

  it("protects safety events with authentication", async () => {
    const app = await createApp(
      loadConfig({
        NODE_ENV: "test",
        APP_AUTH_TOKEN: "a-strong-test-token",
      }),
      service,
    );

    const response = await app.inject({
      method: "GET",
      url: "/api/runs/00000000-0000-0000-0000-000000000000/safety-events",
    });

    expect(response.statusCode).toBe(401);
    await app.close();
  });

  it("does not expose raw prompt or secret fields in safety events", async () => {
    const secret = "sk-" + "a".repeat(24);
    const eventService = {
      ...service,
      getSafetyEvents: () => [
        {
          id: "event-id",
          runId: "00000000-0000-0000-0000-000000000000",
          boundary: "SERVICE",
          decision: "REDACT",
          reason: "Secret removed from trace",
          timestamp: new Date().toISOString(),
          prompt: `Use ${secret}`,
          secret,
        },
      ],
    } as unknown as AgentService;
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), eventService);

    const response = await app.inject({
      method: "GET",
      url: "/api/runs/00000000-0000-0000-0000-000000000000/safety-events",
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).not.toContain(secret);
    expect(response.body).not.toContain("prompt");
    expect(response.body).not.toContain("secret");
    await app.close();
  });

  it("does not expose submitted secrets in validation errors", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);
    const secret = "sk-" + "b".repeat(24);

    const response = await app.inject({
      method: "POST",
      url: "/api/agents",
      headers: { "content-type": "application/json" },
      payload: { name: "", apiKey: secret },
    });

    expect(response.statusCode).toBe(400);
    expect(response.body).not.toContain(secret);
    await app.close();
  });

});
