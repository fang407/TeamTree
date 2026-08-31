import cors from "@fastify/cors";
import fastifyStatic from "@fastify/static";
import Fastify, { type FastifyInstance } from "fastify";
import { timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { AppConfig } from "./config.js";
import { HttpError } from "./errors.js";
import type { AgentService } from "./agent-service.js";
import { validateRequest } from "./validation.js";

const agentIdParams = z
  .object({ id: z.string().uuid() })
  .strict();
const runIdParams = z
  .object({ id: z.string().uuid() })
  .strict();
const createAgentBody = z
  .object({
    name: z.string().trim().min(1).max(80),
    description: z.string().max(500).optional(),
    instructions: z.string().max(10_000).optional(),
  })
  .strict();
const updateAgentBody = createAgentBody
  .partial()
  .strict()
  .refine(
    (value) => Object.keys(value).length > 0,
    "At least one field is required",
  );
const complianceFrameworkSchema = z.enum([
  "GDPR",
  "HIPAA",
  "CCPA",
  "PCI_DSS",
]);
const redactionConfigBody = z
  .object({
    redactionEnabled: z.boolean().optional(),
    complianceFrameworks: z.array(complianceFrameworkSchema).optional(),
    enabledPatternIds: z.array(z.string().min(1).max(100)).max(50).optional(),
    disabledPatternIds: z.array(z.string().min(1).max(100)).max(50).optional(),
  })
  .strict()
  .refine(
    (value) => Object.keys(value).length > 0,
    "At least one field is required",
  );
const reservedSecretNames = new Set([
  "PATH",
  "HOME",
  "TMPDIR",
  "CODEX_HOME",
  "ARK_API_KEY",
  "NO_COLOR",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "NO_PROXY",
]);
const messageBody = z
  .object({
    content: z.string().trim().min(1).max(50_000),
    secrets: z
      .record(
        z
          .string()
          .regex(
            /^[A-Z][A-Z0-9_]{0,63}$/,
            "Secret names must use uppercase letters, numbers, and underscores",
          ),
        z.string().min(1).max(8_192),
      )
      .refine(
        (secrets) => Object.keys(secrets).length <= 20,
        "A maximum of 20 secrets is allowed",
      )
      .refine(
        (secrets) =>
          Object.keys(secrets).every((name) => !reservedSecretNames.has(name)),
        "Secret name conflicts with a reserved environment variable",
      )
      .optional(),
  })
  .strict();

export async function createApp(
  config: AppConfig,
  service: AgentService,
): Promise<FastifyInstance> {
  const app = Fastify({
    logger: {
      level: config.logLevel,
      redact: ["req.headers.authorization", "req.headers.cookie"],
    },
    bodyLimit: 1_048_576,
  });

  app.setErrorHandler((error, request, reply) => {
    const issues = (error as { issues?: unknown }).issues;
    if (Array.isArray(issues)) {
      return reply.code(400).send({
        error: "Request validation failed",
        details: issues.map((issue) => ({
          field:
            issue && typeof issue === "object" && "path" in issue
              ? (issue as { path?: unknown[] }).path?.join(".") || "request"
              : "request",
          message:
            issue && typeof issue === "object" && "message" in issue
              ? String((issue as { message: unknown }).message)
              : "Invalid request",
        })),
      });
    }

    const appError = error instanceof Error ? error : new Error(String(error));

    const frameworkStatus =
      typeof (error as { statusCode?: unknown }).statusCode === "number"
        ? (error as { statusCode: number }).statusCode
        : null;

    const statusCode =
      error instanceof HttpError
        ? error.statusCode
        : frameworkStatus &&
            frameworkStatus >= 400 &&
            frameworkStatus <= 599
          ? frameworkStatus
          : 500;

    if (statusCode >= 500) {
      request.log.error({ err: appError }, "Unhandled server error");

      return reply.code(500).send({
        error: "Internal server error",
      });
    }

    return reply.code(statusCode).send({
      error: appError.message,
    });
  });

  await app.register(cors, {
    origin:
      config.nodeEnv === "development"
        ? ["http://localhost:5173", "http://127.0.0.1:5173"]
        : false,
  });

  app.addHook("onRequest", async (request, reply) => {
    if (
      !config.authToken ||
      !request.url.startsWith("/api/") ||
      request.url === "/api/health" ||
      request.url === "/api/auth"
    ) {
      return;
    }
    const header = request.headers.authorization ?? "";
    const candidate = header.startsWith("Bearer ") ? header.slice(7) : "";
    const expectedBuffer = Buffer.from(config.authToken);
    const candidateBuffer = Buffer.from(candidate);
    const valid =
      candidateBuffer.length === expectedBuffer.length &&
      timingSafeEqual(candidateBuffer, expectedBuffer);
    if (!valid) {
      return reply.code(401).send({ error: "Authentication required" });
    }
  });

  app.get("/api/health", async () => ({
    ok: true,
    service: "volc-agent-launchpad",
  }));

  app.get("/api/auth", async () => ({ required: config.authToken.length > 0 }));

  app.get("/api/system", async () => service.systemInfo());

  app.get("/api/redaction-config", async () => service.getRedactionConfig());

  app.patch(
    "/api/redaction-config",
    { preValidation: validateRequest({ body: redactionConfigBody }) },
    async (request) => {
      const body = redactionConfigBody.parse(request.body);
      return service.updateRedactionConfig(body);
    },
  );

  app.get("/api/secret-signatures", async () => ({
    signatures: service.getSecretSignatures(),
  }));

  app.get("/api/learned-secret-patterns", async () => ({
    patterns: service.getLearnedSecretPatterns(),
  }));

  app.get("/api/agents", async () => ({ agents: service.listAgents() }));

  app.post(
    "/api/agents",
    { preValidation: validateRequest({ body: createAgentBody }) },
    async (request, reply) => {
      const body = createAgentBody.parse(request.body);
      const agent = await service.createAgent(body);
      return reply.code(201).send({ agent });
    }
  );

  app.get(
    "/api/agents/:id",
    { preValidation: validateRequest({ params: agentIdParams }) },
    async (request) => {
      const { id } = agentIdParams.parse(request.params);
      return { agent: service.getAgent(id) };
    },
  );

  app.patch(
    "/api/agents/:id", 
    {
      preValidation: validateRequest({
        params: agentIdParams,
        body: updateAgentBody
      }),
    },
    async (request) => {
      const { id } = agentIdParams.parse(request.params);
      const body = updateAgentBody.parse(request.body);
      return { agent: await service.updateAgent(id, body) };
    }
  );

  app.delete(
    "/api/agents/:id",
    { preValidation: validateRequest({ params: agentIdParams }) },
    async (request) => {
      const { id } = agentIdParams.parse(request.params);
      return service.deleteAgent(id);
    }
  );

  app.post(
    "/api/agents/:id/start", 
    { preValidation: validateRequest({ params: agentIdParams }) },
    async (request) => {
      const { id } = agentIdParams.parse(request.params);
      return { agent: await service.startAgent(id) };
    }
  );

  app.post(
    "/api/agents/:id/stop", 
    { preValidation: validateRequest({ params: agentIdParams }) },
    async (request) => {
      const { id } = agentIdParams.parse(request.params);
      return { agent: await service.stopAgent(id) };
    }
  );

  app.get(
    "/api/agents/:id/messages", 
    { preValidation: validateRequest({ params: agentIdParams }) },
    async (request) => {
      const { id } = agentIdParams.parse(request.params);
      return { messages: service.getMessages(id) };
    }
  );

  app.get(
    "/api/agents/:id/runs",
    { preValidation: validateRequest({ params: agentIdParams }) },
    async (request) => {
      const { id } = agentIdParams.parse(request.params);
      return { runs: service.getRuns(id) };
    }
  );

  app.post(
    "/api/agents/:id/messages",
    {
      preValidation: validateRequest({
        params: agentIdParams,
        body: messageBody,
      }),
    },
    async (request, reply) => {
      const { id } = agentIdParams.parse(request.params);
      const body = messageBody.parse(request.body);
      const result = await service.sendMessage(
        id,
        body.content,
        body.secrets ?? {},
      );
      return reply.code(202).send(result);
    }
  );

  app.get(
    "/api/runs/:id",
    { preValidation: validateRequest({ params: runIdParams }) },
    async (request) => {
      const { id } = runIdParams.parse(request.params);
      return { run: service.getRun(id) };
    }
  );

  app.get(
    "/api/runs/:id/safety-events",
    { preValidation: validateRequest({ params: runIdParams }) },
    async (request) => {
      const { id } = runIdParams.parse(request.params);

      const events = service.getSafetyEvents(id).map((event) => ({
        id: event.id,
        runId: event.runId,
        agentId: event.agentId,
        boundary: event.boundary,
        decision: event.decision,
        reason: event.reason,
        timestamp: event.timestamp,
      }));
      
      return { events };
    },
  );

  if (config.nodeEnv === "production") {
    const webRoot = fileURLToPath(new URL("../../web/dist", import.meta.url));
    await app.register(fastifyStatic, {
      root: webRoot,
      prefix: "/",
    });
    app.setNotFoundHandler((request, reply) => {
      if (request.url.startsWith("/api/")) {
        return reply.code(404).send({ error: "API route not found" });
      }
      return reply.sendFile("index.html");
    });
  }

  return app;
}
