/**
 * Secret detection reference collection.
 *
 * Patterns are curated from the Gitleaks default ruleset
 * (https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml,
 * MIT licensed, 100+ community-maintained secret signatures) plus a small
 * set of generic/keyword-based rules for anything without a distinct
 * prefix (client secrets, DB connection strings, passwords).
 *
 * This file is a DATA collection, not logic — update/extend it independently
 * of safety-middleware.ts as new provider token formats appear or Gitleaks'
 * upstream ruleset changes.
 *
 * Each rule may declare `entropyThreshold` (bits/char, Shannon entropy).
 * When set, a match is only kept if the captured secret value clears that
 * bar — this is the same technique Gitleaks uses to suppress false
 * positives on generic/keyword-based rules (e.g. AWS's own docs example
 * key AKIAIOSFODNN7EXAMPLE has low entropy and gets filtered).
 */

export type SecretSeverity = "low" | "medium" | "high" | "critical";

export interface SecretPattern {
  id: string;
  description: string;
  /** Must be pre-flagged global ("g"); no runtime recompilation. */
  regex: RegExp;
  severity: SecretSeverity;
  /** Minimum Shannon entropy (bits/char) required of the captured value. */
  entropyThreshold?: number;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  // --- Cloud provider keys -------------------------------------------------
  {
    id: "aws-access-key-id",
    description: "AWS Access Key ID",
    regex: /\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
    severity: "critical",
  },
  {
    id: "aws-secret-access-key",
    description: "AWS Secret Access Key (keyword + high-entropy value)",
    regex: /\baws(?:.{0,20})?['"]?([0-9a-zA-Z/+]{40})['"]?/gi,
    severity: "critical",
    entropyThreshold: 4.0,
  },
  {
    id: "gcp-api-key",
    description: "Google Cloud / Firebase API Key",
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    severity: "high",
  },
  {
    id: "azure-storage-key",
    description: "Azure Storage Account Key",
    regex: /\b[A-Za-z0-9+/]{86}==\b/g,
    severity: "high",
    entropyThreshold: 4.2,
  },

  // --- Source control / CI --------------------------------------------------
  {
    id: "github-pat",
    description: "GitHub Personal Access Token",
    regex: /\bghp_[0-9A-Za-z]{36}\b/g,
    severity: "critical",
  },
  {
    id: "github-oauth",
    description: "GitHub OAuth Access Token",
    regex: /\bgho_[0-9A-Za-z]{36}\b/g,
    severity: "critical",
  },
  {
    id: "github-app-token",
    description: "GitHub App / Server-to-Server Token",
    regex: /\bgh[us]_[0-9A-Za-z]{36}\b/g,
    severity: "critical",
  },
  {
    id: "github-refresh-token",
    description: "GitHub Refresh Token",
    regex: /\bghr_[0-9A-Za-z]{36}\b/g,
    severity: "high",
  },
  {
    id: "gitlab-pat",
    description: "GitLab Personal Access Token",
    regex: /\bglpat-[0-9A-Za-z\-]{20}\b/g,
    severity: "critical",
  },
  {
    id: "npm-token",
    description: "npm Access Token",
    regex: /\bnpm_[0-9A-Za-z]{36}\b/g,
    severity: "high",
  },

  // --- LLM / API providers ---------------------------------------------------
  {
    id: "openai-api-key",
    description: "OpenAI API Key",
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
    severity: "critical",
  },
  {
    id: "anthropic-api-key",
    description: "Anthropic API Key",
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    severity: "critical",
  },
  {
    id: "huggingface-token",
    description: "Hugging Face Access Token",
    regex: /\bhf_[A-Za-z0-9]{30,}\b/g,
    severity: "high",
  },

  // --- Payments / messaging ---------------------------------------------------
  {
    id: "stripe-live-key",
    description: "Stripe Live Secret Key",
    regex: /\bsk_live_[0-9A-Za-z]{24,}\b/g,
    severity: "critical",
  },
  {
    id: "stripe-restricted-key",
    description: "Stripe Restricted Key",
    regex: /\brk_live_[0-9A-Za-z]{24,}\b/g,
    severity: "high",
  },
  {
    id: "slack-token",
    description: "Slack Token",
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,72}\b/g,
    severity: "high",
  },
  {
    id: "slack-webhook",
    description: "Slack Incoming Webhook URL",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Za-z]+\/B[0-9A-Za-z]+\/[0-9A-Za-z]+/g,
    severity: "high",
  },

  // --- Generic / structural ---------------------------------------------------
  {
    id: "jwt",
    description: "JSON Web Token",
    regex: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
    severity: "medium",
  },
  {
    id: "private-key-block",
    description: "PEM-encoded private key block",
    regex:
      /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
    severity: "critical",
  },
  {
    id: "bearer-token",
    description: "Bearer authorization header token",
    regex: /\bBearer\s+[A-Za-z0-9._-]{8,}\b/gi,
    severity: "medium",
  },
  {
    id: "db-connection-string",
    description: "Database connection string with embedded credentials",
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s:@/]+:[^\s@/]+@[^\s/]+/gi,
    severity: "critical",
  },
  {
    id: "generic-secret-assignment",
    description:
      "Generic key/secret/password/token assigned to a high-entropy value",
    // Fixes the original middleware's \b-before-"secret" bug, which missed
    // underscore-joined names like client_secret / db_password.
    regex:
      /\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|secret[_-]?key|secret|password|passwd|pwd|auth[_-]?token)\b\s*[:=]\s*["']?([A-Za-z0-9_\-/+.=]{8,})["']?/gi,
    severity: "medium",
    entropyThreshold: 3.0,
  },
];
