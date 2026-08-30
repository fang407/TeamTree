import {
  SECRET_PATTERNS,
  type SecretPattern,
} from "./patterns/secretPatterns.js";

import {
  PROMPT_INJECTION_PATTERNS,
  type InjectionPattern,
} from "./patterns/promptInjectionPatterns.js";

import {
  normalizeForInjectionScan,
  shannonEntropy,
  passesLuhnCheck,
} from "./utils/textUtils.js";

const REDACTED_SECRET = "[REDACTED_SECRET]";
const REDACTED_PII = "[REDACTED_PII]";

type FindingCategory =
  | "secret"
  | "pii"
  | "prompt_injection";

type Severity =
  | "low"
  | "medium"
  | "high"
  | "critical";

interface Finding {
  id: string;
  category: FindingCategory;
  severity: Severity;
  start: number;
  end: number;
  replacement: string;
}

interface PiiPattern {
  id: string;
  regex: RegExp;
  severity: Severity;
  validate?: (matchedText: string) => boolean;
}

const EMAIL_PATTERN: PiiPattern = {
  id: "email-address",
  regex:
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
  severity: "low",
};

const STRICT_PII_PATTERNS: PiiPattern[] = [
  {
    id: "phone-number",
    regex: /\b\+?\d[\d\s()-]{7,}\d\b/g,
    severity: "low",
  },
  {
    id: "us-ssn",
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    severity: "high",
  },
  {
    id: "credit-card-number",
    regex: /\b(?:\d[ -]?){13,19}\b/g,
    severity: "high",
    validate: passesLuhnCheck,
  },
];

export interface SafetyPolicyConfig {
  redactionEnabled: boolean;
  promptSafetyEnabled: boolean;

  compliance: {
    strictPii: boolean;
  };

  injection: {
    blockOn: Severity[];
  };
}

const DEFAULT_POLICY_CONFIG: SafetyPolicyConfig = {
  redactionEnabled: true,
  promptSafetyEnabled: true,

  compliance: {
    strictPii: false,
  },

  injection: {
    blockOn: ["critical", "high"],
  },
};

export interface SafetyFindingSummary {
  id: string;
  category: FindingCategory;
  severity: Severity;
}

export interface SafetyCheckResult {
  decision: "ALLOW" | "BLOCK";
  reason: string;
  redactedPrompt: string;
  wasRedacted: boolean;

  /**
   * Contains rule metadata only.
   * Never contains the matched secret/PII text.
   */
  findings: SafetyFindingSummary[];
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

    // Stage 1: secret + PII detection on the raw prompt.
    //
    // Raw text is required here because offsets are later
    // used to redact the original prompt.
    if (this.config.redactionEnabled) {
      findings.push(...this.detectSecrets(prompt));
      findings.push(...this.detectPii(prompt));
    }

    // Stage 2: prompt-injection detection.
    //
    // Injection scanning can safely use normalized text
    // because injection findings are never used for
    // redaction offsets.
    let injectionFindings: Finding[] = [];

    if (this.config.promptSafetyEnabled) {
      const normalizedPrompt =
        normalizeForInjectionScan(prompt);

      injectionFindings =
        this.detectPromptInjection(normalizedPrompt);

      findings.push(...injectionFindings);
    }

    // Stage 3: deterministic policy decision.
    const decision =
      this.decide(injectionFindings);

    // Stage 4: redact secrets and PII only.
    const redactionFindings = findings.filter(
      (finding) =>
        finding.category !== "prompt_injection",
    );

    const redactedPrompt = this.redact(
      prompt,
      redactionFindings,
    );

    return {
      decision,
      reason: this.buildReason(
        decision,
        injectionFindings,
      ),
      redactedPrompt,
      wasRedacted: redactedPrompt !== prompt,

      // Expose metadata only, never matched text.
      findings: findings.map(
        ({ id, category, severity }) => ({
          id,
          category,
          severity,
        }),
      ),
    };
  }

  private decide(
    injectionFindings: Finding[],
  ): SafetyCheckResult["decision"] {
    const shouldBlock = injectionFindings.some(
      (finding) =>
        this.config.injection.blockOn.includes(
          finding.severity,
        ),
    );

    return shouldBlock
      ? "BLOCK"
      : "ALLOW";
  }

  private buildReason(
    decision: SafetyCheckResult["decision"],
    injectionFindings: Finding[],
  ): string {
    if (decision === "ALLOW") {
      return "Request passed safety checks";
    }

    const matchedRuleIds = [
      ...new Set(
        injectionFindings
          .filter((finding) =>
            this.config.injection.blockOn.includes(
              finding.severity,
            ),
          )
          .map((finding) => finding.id),
      ),
    ];

    return `Blocked: matched ${
      matchedRuleIds.join(", ") || "policy rule"
    }`;
  }

  private detectSecrets(
    prompt: string,
  ): Finding[] {
    const findings: Finding[] = [];

    for (
      const pattern of SECRET_PATTERNS as SecretPattern[]
    ) {
      for (const match of prompt.matchAll(pattern.regex)) {
        if (match.index === undefined) {
          continue;
        }

        if (
          pattern.entropyThreshold !== undefined
        ) {
          const capturedValue =
            match[1] ?? match[0];

          if (
            shannonEntropy(capturedValue) <
            pattern.entropyThreshold
          ) {
            continue;
          }
        }

        findings.push({
          id: pattern.id,
          category: "secret",
          severity: pattern.severity,
          start: match.index,
          end: match.index + match[0].length,
          replacement: REDACTED_SECRET,
        });
      }
    }

    return findings;
  }

  private detectPii(
    prompt: string,
  ): Finding[] {
    const findings: Finding[] = [];

    const activePatterns: PiiPattern[] = [
      // Email is sufficiently structured and low-cost
      // to redact whenever redaction is enabled.
      EMAIL_PATTERN,

      // Strict compliance adds more aggressive PII rules.
      ...(this.config.compliance.strictPii
        ? STRICT_PII_PATTERNS
        : []),
    ];

    for (const pattern of activePatterns) {
      for (const match of prompt.matchAll(pattern.regex)) {
        if (match.index === undefined) {
          continue;
        }

        if (
          pattern.validate &&
          !pattern.validate(match[0])
        ) {
          continue;
        }

        findings.push({
          id: pattern.id,
          category: "pii",
          severity: pattern.severity,
          start: match.index,
          end: match.index + match[0].length,
          replacement: REDACTED_PII,
        });
      }
    }

    return findings;
  }

  private detectPromptInjection(
    normalizedPrompt: string,
  ): Finding[] {
    const findings: Finding[] = [];

    for (
      const pattern of
        PROMPT_INJECTION_PATTERNS as InjectionPattern[]
    ) {
      for (
        const match of normalizedPrompt.matchAll(
          pattern.regex,
        )
      ) {
        if (match.index === undefined) {
          continue;
        }

        findings.push({
          id: pattern.id,
          category: "prompt_injection",
          severity: pattern.severity,
          start: match.index,
          end: match.index + match[0].length,
          replacement: "",
        });
      }
    }

    // Cheap compound heuristic for common
    // encoded-payload execution phrasing.
    //
    // Medium severity means it is recorded as a finding
    // under the default policy but does not BLOCK.
    if (
      /\bbase64\b/i.test(normalizedPrompt) &&
      /\b(?:decode|execute|run)\b/i.test(
        normalizedPrompt,
      )
    ) {
      findings.push({
        id: "base64-decode-execute-heuristic",
        category: "prompt_injection",
        severity: "medium",
        start: 0,
        end: 0,
        replacement: "",
      });
    }

    return findings;
  }

  private redact(
    prompt: string,
    findings: Finding[],
  ): string {
    let result = prompt;

    // Work backwards so replacing one span does not shift
    // the offsets of spans that occur earlier in the text.
    const ordered = [...findings].sort(
      (left, right) =>
        right.start - left.start,
    );

    let previousStart = prompt.length;

    for (const finding of ordered) {
      // Skip overlapping findings already covered by a
      // later/larger replacement.
      if (finding.end > previousStart) {
        continue;
      }

      result =
        result.slice(0, finding.start) +
        finding.replacement +
        result.slice(finding.end);

      previousStart = finding.start;
    }

    return result;
  }
}