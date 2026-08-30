import {
  SECRET_PATTERNS,
  type SecretPattern,
} from "./patterns/secretPatterns.js";

import {
  PROMPT_INJECTION_PATTERNS,
  type InjectionPattern,
} from "./patterns/promptInjectionPatterns.js";

import {
  BASELINE_PII_PATTERNS,
  FRAMEWORK_PII_PATTERNS,
  type ComplianceFramework,
  type PiiPattern,
} from "./patterns/compliancePatterns.js";

import {
  normalizeForInjectionScan,
  shannonEntropy,
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

export interface SafetyPolicyConfig {
  redactionEnabled: boolean;
  promptSafetyEnabled: boolean;

  compliance: {
    /**
     * Which compliance frameworks' PII identifier sets are active. Empty
     * array = baseline only (email). Multiple frameworks can be enabled at
     * once — realistic for a deployment spanning jurisdictions or product
     * lines. See patterns/compliancePatterns.ts for what each framework
     * actually gates, and its stated limitations.
     */
    frameworks: ComplianceFramework[];
  };

  injection: {
    blockOn: Severity[];
  };
}

export const DEFAULT_POLICY_CONFIG: SafetyPolicyConfig = {
  redactionEnabled: true,
  promptSafetyEnabled: true,

  compliance: {
    // GDPR + CCPA cover the two jurisdictions any consumer product with
    // EU or US(-CA) users almost certainly needs by default. HIPAA and
    // PCI_DSS stay opt-in — they only apply if the deployment actually
    // handles health or payment-card data, which this middleware can't
    // know on its own. Note: because CCPA's "personal information"
    // definition is broad, this default activates most patterns except
    // the two that are HIPAA-exclusive (medical-record-number,
    // medicare-beneficiary-id) — see patterns/compliancePatterns.ts for
    // the full per-pattern framework tagging.
    frameworks: ["GDPR", "CCPA"],
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

    const activeFrameworks = this.config.compliance.frameworks;

    const activePatterns: PiiPattern[] = [
      // Baseline patterns (currently just email) are always active,
      // independent of framework selection.
      ...BASELINE_PII_PATTERNS,

      // Framework-gated patterns only run if at least one of the
      // pattern's tagged frameworks is enabled in config.
      ...FRAMEWORK_PII_PATTERNS.filter((pattern) =>
        pattern.frameworks.some((framework) =>
          activeFrameworks.includes(framework),
        ),
      ),
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

  redactText(value: string): string {
    const findings: Finding[] = [];

    if (this.config.redactionEnabled) {
      findings.push(...this.detectSecrets(value));
      findings.push(...this.detectPii(value));
    }

    return this.redact(value, findings);
  }

  private redact(
    prompt: string,
    findings: Finding[],
  ): string {
    let result = prompt;

    // Selecting which findings to keep must happen left-to-right and must
    // prefer the longer match when spans start at the same point or one
    // contains another — otherwise a small pattern nested inside a larger
    // one (e.g. a "phone number"-shaped digit run inside a Slack token,
    // which is a real overlap once PII detection runs alongside secret
    // detection) can silently steal the redaction and leave the outer,
    // more-specific match un-redacted. Sorting by (start ascending, length
    // descending) and greedily keeping only non-overlapping spans is the
    // standard fix for this class of bug.
    const bySelectionOrder = [...findings].sort((left, right) => {
      if (left.start !== right.start) return left.start - right.start;
      return (right.end - right.start) - (left.end - left.start);
    });

    const kept: Finding[] = [];
    let cursor = 0;
    for (const finding of bySelectionOrder) {
      if (finding.start < cursor) {
        continue; // overlaps a span already claimed by an earlier, longer/earlier-starting match
      }
      kept.push(finding);
      cursor = finding.end;
    }

    // Now apply the kept, non-overlapping findings. Splicing must happen
    // right-to-left so replacing one span doesn't shift the offsets of
    // spans that occur earlier in the text.
    const byApplicationOrder = [...kept].sort(
      (left, right) => right.start - left.start,
    );

    for (const finding of byApplicationOrder) {
      result =
        result.slice(0, finding.start) +
        finding.replacement +
        result.slice(finding.end);
    }

    return result;
  }
}