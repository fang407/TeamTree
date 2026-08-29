import { describe, expect, it } from "vitest";
import {
  SafetyVault,
  checkExecutionPrompt,
  secretConfidence,
} from "./safety-middleware.js";

describe("SafetyVault", () => {
  it("replaces a secret with an opaque placeholder and restores it only from the vault", () => {
    const vault = new SafetyVault();
    const result = vault.redactText("Deploy with sk-abcdefghijklmnopqrstuvwxyz0123456789");

    expect(result.value).not.toContain("abcdefghijklmnopqrstuvwxyz0123456789");
    expect(result.value).toContain("[PRIVATE_API_KEY_");
    expect(vault.restoreText(result.value)).toBe(
      "Deploy with sk-abcdefghijklmnopqrstuvwxyz0123456789",
    );
  });
});

describe("high-entropy classifier", () => {
  it("scores secret-like entropy higher than common look-alikes", () => {
    const secret = "z9Lq_7VzN2pQ4xR8mK1dW5yT0aB3cF6hJ9sE2uI4oP7g";
    const uuid = "550e8400-e29b-41d4-a716-446655440000";
    const gitSha = "d3486ae9136e7856bc42212385ea797094475802";
    const base64 = "QmFzZTY0RW5jb2RlZEJ1dE5vdFNlY3JldA==";

    expect(secretConfidence(uuid)).toBeLessThan(0.1);
    expect(secretConfidence(gitSha)).toBeLessThan(0.1);
    expect(secretConfidence(base64)).toBeLessThan(0.2);
    expect(checkExecutionPrompt("Use ghp_abcdefghijklmnopqrstuvwxyz0123456789").decision).toBe(
      "REDACT",
    );
    expect(secretConfidence(secret)).toBeGreaterThan(0.1);
  });

  it("honours the configurable confidence threshold", () => {
    const prompt = "Use z9Lq_7VzN2pQ4xR8mK1dW5yT0aB3cF6hJ9sE2uI4oP7g";

    expect(checkExecutionPrompt(prompt, { minConfidence: 0.1 }).decision).toBe("REDACT");
    expect(checkExecutionPrompt(prompt, { minConfidence: 0.9 }).decision).toBe("ALLOW");
  });
});
