const REDACTED_SECRET = "[REDACTED_SECRET]";

type FindingCategory =
  | "secret"
  | "pii"
  | "prompt_injection";

interface Finding {
  category: FindingCategory;
  start: number;
  end: number;
}

interface Detector {
  category: FindingCategory;
  pattern: RegExp;
}

const SECRET_DETECTORS: Detector[] = [
  {
    category: "secret",
    pattern: /\bsk-[A-Za-z0-9_-]{8,}\b/g,
  },
  {
    category: "secret",
    pattern: /\bAKIA[A-Z0-9]{16}\b/g,
  },
  {
    category: "secret",
    pattern: /\bBearer\s+[A-Za-z0-9._-]{8,}\b/gi,
  },
  {
    category: "secret",
    pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
  },
  {
    category: "secret",
    pattern:
      /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
  },
  {
    category: "secret",
    pattern:
      /\b(?:api[_-]?key|access[_-]?token|secret)\s*[:=]\s*["']?[A-Za-z0-9._-]{8,}["']?/gi,
  },
];

const PII_DETECTORS: Detector[] = [
  {
    category: "pii",
    pattern:
      /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
  },
  {
    category: "pii",
    pattern:
      /\b(?:\+?\d[\d\s()-]{7,}\d)\b/g,
  },
];

const SUSPICIOUS_DETECTORS: Detector[] = [
  {
    category: "prompt_injection",
    pattern:
      /\bignore\s+(all\s+)?previous\s+instructions?\b/i,
  },
  {
    category: "prompt_injection",
    pattern: /\bdelete\s+all\s+files?\b/i,
  },
];

export interface SafetyPolicyConfig {
  redactionEnabled: boolean;
  promptSafetyEnabled: boolean;

  compliance: {
    strictPii: boolean;
  };
}

const DEFAULT_POLICY_CONFIG: SafetyPolicyConfig = {
  redactionEnabled: true,
  promptSafetyEnabled: true,

  compliance: {
    strictPii: false,
  },
};

export interface SafetyCheckResult {
  decision: "ALLOW" | "BLOCK";
  reason: string;
  redactedPrompt: string;
  wasRedacted: boolean;
}

export class SafetyMiddleware {
  constructor(
    private readonly config: SafetyPolicyConfig =
      DEFAULT_POLICY_CONFIG,
  ) {}

  async evaluate(
    prompt: string,
  ): Promise<SafetyCheckResult> {
    const findings: Finding[] = [];

    if (this.config.redactionEnabled) {
      findings.push(
        ...this.detect(prompt, SECRET_DETECTORS),
      );

      if (this.config.compliance.strictPii) {
        findings.push(
          ...this.detect(prompt, PII_DETECTORS),
        );
      }
    }

    if (this.config.promptSafetyEnabled) {
      findings.push(
        ...this.detect(prompt, SUSPICIOUS_DETECTORS),
      );
    }

    const blocked = findings.some(
      (finding) =>
        finding.category === "prompt_injection",
    );

    const redactionFindings = findings.filter(
      (finding) =>
        finding.category === "secret" ||
        finding.category === "pii",
    );

    const redactedPrompt = this.redact(
      prompt,
      redactionFindings,
    );

    return {
      decision: blocked ? "BLOCK" : "ALLOW",
      reason: blocked
        ? "Suspicious instruction detected"
        : "Request passed safety checks",
      redactedPrompt,
      wasRedacted: redactedPrompt !== prompt,
    };
  }

  private detect(
    prompt: string,
    detectors: Detector[],
  ): Finding[] {
    const findings: Finding[] = [];

    for (const detector of detectors) {
      const flags = detector.pattern.flags.includes("g")
        ? detector.pattern.flags
        : `${detector.pattern.flags}g`;

      const pattern = new RegExp(
        detector.pattern.source,
        flags,
      );

      for (const match of prompt.matchAll(pattern)) {
        if (match.index === undefined) {
          continue;
        }

        findings.push({
          category: detector.category,
          start: match.index,
          end: match.index + match[0].length,
        });
      }
    }

    return findings;
  }

  private redact(
    prompt: string,
    findings: Finding[],
  ): string {
    let result = prompt;

    const ordered = [...findings].sort(
      (left, right) => right.start - left.start,
    );

    let previousStart = prompt.length;

    for (const finding of ordered) {
      if (finding.end > previousStart) {
        continue;
      }

      result =
        result.slice(0, finding.start) +
        REDACTED_SECRET +
        result.slice(finding.end);

      previousStart = finding.start;
    }

    return result;
  }
}