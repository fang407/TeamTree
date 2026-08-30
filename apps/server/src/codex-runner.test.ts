import { describe, expect, it } from "vitest";
import { buildCodexArgs, parseCodexEventLine } from "./codex-runner.js";

describe("Codex runner protocol", () => {
  it("builds a new-session invocation", () => {
    const args = buildCodexArgs(
      {
        agentId: "agent",
        workspacePath: "/tmp/workspace",
        prompt: "build a calculator",
        threadId: null,
      },
      "workspace-write",
    );
    expect(args).toEqual([
      "exec",
      "--json",
      "--sandbox",
      "workspace-write",
      "--skip-git-repo-check",
      "-C",
      "/tmp/workspace",
      "build a calculator",
    ]);
  });

  it("resumes a stored Codex thread", () => {
    const args = buildCodexArgs(
      {
        agentId: "agent",
        workspacePath: "/tmp/workspace",
        prompt: "add tests",
        threadId: "thread-123",
      },
      "workspace-write",
    );
    expect(args.slice(-3)).toEqual(["resume", "thread-123", "add tests"]);
  });

  it("extracts the session, final message and usage", () => {
    const parsed = {
      messages: [] as string[],
      threadId: null as string | null,
      usage: null as {
        inputTokens?: number;
        cachedInputTokens?: number;
        outputTokens?: number;
      } | null,
      errors: [] as string[],
    };
    parseCodexEventLine(
      JSON.stringify({ type: "thread.started", thread_id: "thread-123" }),
      parsed,
    );
    parseCodexEventLine(
      JSON.stringify({
        type: "item.completed",
        item: { type: "agent_message", text: "Done." },
      }),
      parsed,
    );
    parseCodexEventLine(
      JSON.stringify({
        type: "turn.completed",
        usage: { input_tokens: 10, output_tokens: 4 },
      }),
      parsed,
    );
    expect(parsed.threadId).toBe("thread-123");
    expect(parsed.messages).toEqual(["Done."]);
    expect(parsed.usage).toEqual({ inputTokens: 10, outputTokens: 4 });
  });

  it("counts total steps and buckets tool calls by type", () => {
    const parsed: {
      messages: string[];
      threadId: string | null;
      usage: null;
      errors: string[];
      stepCount?: number;
      toolCalls?: { commands: number; fileEdits: number; other: number };
    } = {
      messages: [],
      threadId: null,
      usage: null,
      errors: [],
    };

    const completed = (item: Record<string, unknown>) =>
      parseCodexEventLine(JSON.stringify({ type: "item.completed", item }), parsed);

    completed({ type: "reasoning", text: "Thinking about it" });
    completed({ type: "command_execution", command: "ls" });
    completed({ type: "command_execution", command: "cat README.md" });
    completed({ type: "file_change", path: "README.md" });
    completed({ type: "mcp_tool_call", server: "docs", tool: "search" });
    completed({ type: "agent_message", text: "Done." });

    // 6 completed items total ("steps"); reasoning and the final
    // agent_message aren't actions, so they don't appear in the tool-call
    // breakdown, but they still count toward the step total.
    expect(parsed.stepCount).toBe(6);
    expect(parsed.toolCalls).toEqual({ commands: 2, fileEdits: 1, other: 1 });
  });
});
