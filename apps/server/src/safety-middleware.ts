const REDACTED_SECRET = "[REDACTED_SECRET]";

const SECRET_PATTERNS = [
  /\bsk-[A-Za-z0-9_-]{8,}\b/g,
  /\bAKIA[A-Z0-9]{16}\b/g,
  /\bBearer\s+[A-Za-z0-9._-]{8,}\b/gi,
];

const SUSPICIOUS_PATTERNS = [
  /\bignore\s+(all\s+)?previous\s+instructions?\b/i,
  /\bdelete\s+all\s+files?\b/i,
];

export interface SafetyCheckResult {
  decision: "ALLOW" | "BLOCK";
  reason: string;
  redactedPrompt: string;
  wasRedacted: boolean;
}

export class SafetyMiddleware {
  async evaluate(prompt: string): Promise<SafetyCheckResult> {
    const redactedPrompt = this.redactSecrets(prompt);
    const wasRedacted = redactedPrompt !== prompt;

    const blocked = SUSPICIOUS_PATTERNS.some((pattern) =>
      pattern.test(prompt),
    );

    if (blocked) {
      return {
        decision: "BLOCK",
        reason: "Suspicious instruction detected",
        redactedPrompt,
        wasRedacted,
      };
    }

    return {
      decision: "ALLOW",
      reason: "Request passed safety checks",
      redactedPrompt,
      wasRedacted,
    };
  }

  private redactSecrets(value: string): string {
    return SECRET_PATTERNS.reduce(
      (redacted, pattern) => redacted.replace(pattern, REDACTED_SECRET),
      value,
    );
  }
}