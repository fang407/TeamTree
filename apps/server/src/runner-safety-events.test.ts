import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CodexRunner } from "./codex-runner.js";
import { loadConfig } from "./config.js";
import { ContainerCodexRunner } from "./container-codex-runner.js";
import type { RunnerRequest, RunnerSafetyEvent } from "./types.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function fakeExecutable(program: string): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "launchpad-runner-test-"));
  temporaryDirectories.push(directory);
  const executable = path.join(directory, "runner.mjs");
  await writeFile(executable, "#!/usr/bin/env node\n" + program, { mode: 0o700 });
  await chmod(executable, 0o700);
  return executable;
}

function request(events: RunnerSafetyEvent[]): RunnerRequest {
  return {
    agentId: "runner-test-agent",
    workspacePath: os.tmpdir(),
    prompt: "test",
    threadId: null,
    onSafetyEvent: async (event) => {
      events.push(event);
    },
  };
}

function localConfig(codexBin: string, overrides: Record<string, string> = {}) {
  return loadConfig({
    NODE_ENV: "test",
    CODEX_BIN: codexBin,
    CODEX_HOME: os.tmpdir(),
    CODEX_TIMEOUT_MS: "3000",
    CODEX_MAX_OUTPUT_BYTES: "65536",
    ...overrides,
  });
}

describe("Runner safety events", () => {
  it("records a local execution start and successful result", async () => {
    const executable = await fakeExecutable(`
      console.log(JSON.stringify({ type: "thread.started", thread_id: "thread-test" }));
      console.log(JSON.stringify({ type: "item.completed", item: { type: "agent_message", text: "Done" } }));
    `);
    const events: RunnerSafetyEvent[] = [];
    const runner = new CodexRunner(localConfig(executable));

    await expect(runner.run(request(events))).resolves.toMatchObject({ output: "Done" });
    expect(events).toEqual([{ decision: "ALLOW", reason: "Execution started" }]);
  });

  it("records timeout cancellation", async () => {
    const executable = await fakeExecutable("setTimeout(() => {}, 5000);");
    const events: RunnerSafetyEvent[] = [];
    const runner = new CodexRunner(localConfig(executable, { CODEX_TIMEOUT_MS: "1000" }));

    await expect(runner.run(request(events))).rejects.toThrow("timed out");
    expect(events).toContainEqual({ decision: "CANCELLED", reason: "Timeout exceeded" });
  });

  it("records user cancellation", async () => {
    const executable = await fakeExecutable("setTimeout(() => {}, 5000);");
    const events: RunnerSafetyEvent[] = [];
    const runner = new CodexRunner(localConfig(executable));
    const execution = runner.run(request(events));

    await new Promise((resolve) => setTimeout(resolve, 40));
    await expect(runner.cancel("runner-test-agent")).resolves.toBe(true);
    await expect(execution).rejects.toThrow("Run cancelled");
    expect(events).toContainEqual({ decision: "CANCELLED", reason: "User stopped execution" });
  });

  it("records output-limit blocks and surfaces failed processes", async () => {
    const outputExecutable = await fakeExecutable("process.stdout.write('x'.repeat(70000));");
    const outputEvents: RunnerSafetyEvent[] = [];
    await expect(
      new CodexRunner(localConfig(outputExecutable, { CODEX_TIMEOUT_MS: "10000" })).run(
        request(outputEvents),
      ),
    ).rejects.toThrow(
      "output exceeded",
    );
    expect(outputEvents).toContainEqual({ decision: "BLOCK", reason: "Output limit exceeded" });

    const failureExecutable = await fakeExecutable("process.stderr.write('expected failure'); process.exit(2);");
    await expect(new CodexRunner(localConfig(failureExecutable)).run(request([]))).rejects.toThrow(
      "exited with code 2",
    );
  });

  it("records execution start through the container Runner path", async () => {
    const engine = await fakeExecutable(`
      if (process.argv[2] === "run") {
        console.log(JSON.stringify({ type: "item.completed", item: { type: "agent_message", text: "Container done" } }));
      }
    `);
    const events: RunnerSafetyEvent[] = [];
    const runner = new ContainerCodexRunner(
      localConfig(engine, {
        RUNTIME_PROVIDER: "container",
        CONTAINER_ENGINE: engine,
        CONTAINER_RUNTIME_IMAGE: "test-runtime",
      }),
    );

    await expect(runner.run(request(events))).resolves.toMatchObject({ output: "Container done" });
    expect(events).toEqual([{ decision: "ALLOW", reason: "Execution started" }]);
  });
});
