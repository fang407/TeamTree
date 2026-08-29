import { randomUUID } from "node:crypto";
import type { SafetyDecision } from "./types.js";

export type RedactionDetector =
  | "api_key"
  | "bearer_token"
  | "credential_field"
  | "email"
  | "credit_card"
  | "high_entropy_secret";

export interface RedactionFinding {
  detector: RedactionDetector;
  risk: "medium" | "high";
  location: "text" | "field";
  confidence: number;
}

export interface RedactionResult<T> {
  value: T;
  findings: RedactionFinding[];
}

interface TextDetector {
  detector: RedactionDetector;
  risk: RedactionFinding["risk"];
  pattern: RegExp;
}

const TEXT_DETECTORS: readonly TextDetector[] = [
  {
    detector: "api_key",
    risk: "high",
    pattern: /\b(?:sk|ghp|github_pat|AKIA)[A-Za-z0-9_-]{16,}\b/g,
  },
  {
    detector: "bearer_token",
    risk: "high",
    pattern: /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b/gi,
  },
  {
    detector: "email",
    risk: "medium",
    pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
  },
  {
    detector: "credit_card",
    risk: "high",
    pattern: /\b(?:\d[ -]?){13,19}\b/g,
  },
];

const SENSITIVE_FIELD_NAME = /(?:api[_-]?key|authorization|bearer|secret|token|password|passwd|credential)/i;
const HIGH_ENTROPY_CANDIDATE = /\b[A-Za-z0-9_+/=-]{20,160}(?![A-Za-z0-9_+/=-])/g;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX_DIGEST = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i;

/**
 * Trained locally from 14,274 labelled CredData value spans (80/20 split).
 * Validation: precision 0.9346, recall 0.7566, F1 0.8363. These values are
 * numeric model artefacts only; no CredData sample is shipped with this SDK.
 */
export const TRAINED_SECRET_LOGIT_MODEL = {
  bias: -1.14011961,
  entropy: -0.24854544,
  length: 0.47888893,
  mixedClasses: 0.32521857,
  knownSecretPrefix: 0.12717258,
  uuid: 0.08022316,
  hexDigest: 0.59622159,
  ordinaryBase64: 2.49595596,
} as const;

export interface RedactionOptions {
  /** Candidates below this score are retained to reduce false positives. */
  minConfidence?: number;
}

const BLOCKED_PROMPT_RULES: ReadonlyArray<{ pattern: RegExp; reason: string }> = [
  {
    pattern: /\brm\s+-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*\s+(?:\/|~|\$HOME)(?:\s|$)/i,
    reason: "Destructive recursive deletion of a filesystem root is not allowed",
  },
  {
    pattern: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b/i,
    reason: "Piping downloaded content directly into a shell is not allowed",
  },
];

export interface ExecutionSafetyResult {
  decision: Extract<SafetyDecision, "ALLOW" | "BLOCK" | "REDACT">;
  reason: string;
  safePrompt: string;
  findings: RedactionFinding[];
  vault: SafetyVault;
}

export class SafetyBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SafetyBlockedError";
  }
}

/**
 * A per-run, in-memory vault. It replaces a detected value with a unique,
 * opaque placeholder. Only the holder of this instance can restore it.
 * Never serialize or log this object: its mapping contains the original data.
 */
export class SafetyVault {
  private readonly originalToPlaceholder = new Map<string, string>();
  private readonly placeholderToOriginal = new Map<string, string>();
  private readonly minConfidence: number;

  constructor(options: RedactionOptions = {}) {
    this.minConfidence = clamp(options.minConfidence ?? 0.72, 0, 1);
  }

  redactText(text: string): RedactionResult<string> {
    const findings: RedactionFinding[] = [];
    let safeText = text;

    for (const detector of TEXT_DETECTORS) {
      safeText = safeText.replace(detector.pattern, (value) => {
        findings.push({
          detector: detector.detector,
          risk: detector.risk,
          location: "text",
          confidence: 1,
        });
        return this.placeholderFor(value, detector.detector);
      });
    }

    safeText = safeText.replace(HIGH_ENTROPY_CANDIDATE, (value) => {
      const confidence = secretConfidence(value);
      if (confidence < this.minConfidence) return value;
      findings.push({
        detector: "high_entropy_secret",
        risk: "high",
        location: "text",
        confidence,
      });
      return this.placeholderFor(value, "high_entropy_secret");
    });

    return { value: safeText, findings };
  }

  redactValue<T>(input: T): RedactionResult<T> {
    const findings: RedactionFinding[] = [];
    const value = this.redactUnknown(input, findings) as T;
    return { value, findings };
  }

  restoreText(text: string): string {
    let restored = text;
    for (const [placeholder, original] of this.placeholderToOriginal) {
      restored = restored.replaceAll(placeholder, original);
    }
    return restored;
  }

  private redactUnknown(value: unknown, findings: RedactionFinding[]): unknown {
    if (typeof value === "string") {
      const result = this.redactText(value);
      findings.push(...result.findings);
      return result.value;
    }
    if (Array.isArray(value)) {
      return value.map((item) => this.redactUnknown(item, findings));
    }
    if (!isPlainObject(value)) return value;

    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => {
        if (SENSITIVE_FIELD_NAME.test(key) && item !== null && item !== undefined) {
          findings.push({
            detector: "credential_field",
            risk: "high",
            location: "field",
            confidence: 1,
          });
          return [key, this.placeholderFor(String(item), "credential_field")];
        }
        return [key, this.redactUnknown(item, findings)];
      }),
    );
  }

  private placeholderFor(original: string, detector: RedactionDetector): string {
    const existing = this.originalToPlaceholder.get(original);
    if (existing) return existing;

    const placeholder = "[PRIVATE_" + detector.toUpperCase() + "_" + randomUUID() + "]";
    this.originalToPlaceholder.set(original, placeholder);
    this.placeholderToOriginal.set(placeholder, original);
    return placeholder;
  }
}

/** Creates a masked copy without retaining a vault. Use a SafetyVault for restoration. */
export function redact<T>(input: T): T {
  return new SafetyVault().redactValue(input).value;
}

/** Performs the Runner's pre-execution prompt check and creates its vault. */
export function checkExecutionPrompt(
  prompt: string,
  options?: RedactionOptions,
): ExecutionSafetyResult {
  const vault = new SafetyVault(options);
  const { value: safePrompt, findings } = vault.redactText(prompt);
  const blockedRule = BLOCKED_PROMPT_RULES.find(({ pattern }) => pattern.test(prompt));

  if (blockedRule) {
    return { decision: "BLOCK", reason: blockedRule.reason, safePrompt, findings, vault };
  }
  if (findings.length > 0) {
    return {
      decision: "REDACT",
      reason: "Sensitive values were replaced with private placeholders",
      safePrompt,
      findings,
      vault,
    };
  }
  return {
    decision: "ALLOW",
    reason: "Prompt passed the Runner safety policy",
    safePrompt,
    findings,
    vault,
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false;
  return Object.getPrototypeOf(value) === Object.prototype;
}

/** Shannon entropy in bits per character. Higher scores indicate less repetition. */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const frequencies = new Map<string, number>();
  for (const character of value) {
    frequencies.set(character, (frequencies.get(character) ?? 0) + 1);
  }
  return [...frequencies.values()].reduce((entropy, count) => {
    const probability = count / value.length;
    return entropy - probability * Math.log2(probability);
  }, 0);
}

/**
 * Offline logistic-regression score for unknown high-entropy strings. The
 * coefficients are trained from CredData; runtime guardrails still prevent
 * known non-secret identifiers from being promoted by corpus bias.
 */
export function secretConfidence(candidate: string): number {
  const compact = candidate.replace(/[\s-]/g, "");
  const length = Math.min(compact.length, 128) / 128;
  const entropy = Math.min(shannonEntropy(compact), 6) / 6;
  const mixedClasses = Number(
    /[a-z]/.test(compact) && /[A-Z]/.test(compact) && /\d/.test(compact),
  );
  const knownSecretPrefix = Number(/^(?:sk|ghp|github_pat|AKIA|xox[baprs])-?/i.test(compact));
  const uuid = Number(UUID.test(candidate));
  const digest = Number(HEX_DIGEST.test(compact));
  const base64 = Number(isOrdinaryBase64(compact));

  // CredData intentionally labels some Base64 test fixtures as credentials.
  // In this product, UUIDs and Git-like digests are never secrets, while an
  // otherwise uncontextualized Base64 blob needs a stricter confidence bar.
  if (uuid || digest) return 0;

  const logit =
    TRAINED_SECRET_LOGIT_MODEL.bias +
    TRAINED_SECRET_LOGIT_MODEL.entropy * entropy +
    TRAINED_SECRET_LOGIT_MODEL.length * length +
    TRAINED_SECRET_LOGIT_MODEL.mixedClasses * mixedClasses +
    TRAINED_SECRET_LOGIT_MODEL.knownSecretPrefix * knownSecretPrefix +
    TRAINED_SECRET_LOGIT_MODEL.uuid * uuid +
    TRAINED_SECRET_LOGIT_MODEL.hexDigest * digest +
    TRAINED_SECRET_LOGIT_MODEL.ordinaryBase64 * base64;
  const score = 1 / (1 + Math.exp(-logit));
  return base64 && !knownSecretPrefix ? score * 0.2 : score;
}

function isOrdinaryBase64(value: string): boolean {
  if (value.length < 24 || value.length % 4 !== 0) return false;
  return /^[A-Za-z0-9+/]+={0,2}$/.test(value);
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, value));
}
