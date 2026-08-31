/**
 * Compliance PII detection reference collection.
 *
 * Each pattern is tagged with the compliance framework(s) it's relevant
 * to, so a deployment can select which frameworks apply to it (e.g. a
 * company operating in the EU and US, or running both a general product
 * and a health-adjacent one, needs several active at once — this is
 * deliberately a set, not a single choice).
 *
 * IMPORTANT LIMITATION — read this before treating framework selection as
 * a compliance guarantee: GDPR and HIPAA are legal/organizational
 * obligations, not file formats. Regex can only catch the *structured
 * identifiers* each framework's own guidance names (SSN, MBI, card PAN,
 * IP address, etc). It cannot detect "personal data" in the GDPR sense —
 * a name mentioned in prose, an inferred trait, a pseudonymized ID tied to
 * a person by an external table — and enabling a framework here does not
 * make a product compliant with it. This is one input to a compliance
 * program (traceable, auditable redaction of known identifier shapes),
 * not the program itself. Treat any pattern below with a "generic" or
 * "heuristic" note as lower-confidence than the secret-detection patterns
 * elsewhere in this codebase, which match fixed, well-documented formats.
 *
 * This file is a DATA collection, not logic — extend it independently of
 * safety-middleware.ts as frameworks evolve or new jurisdictions are added.
 */

import { passesLuhnCheck, passesAbaRoutingChecksum } from "../utils/textUtils.js";

export type ComplianceFramework =
  | "GDPR" // EU General Data Protection Regulation
  | "HIPAA" // US health data (Safe Harbor 18-identifier list)
  | "CCPA" // California Consumer Privacy Act / CPRA — representative of US state privacy law
  | "PCI_DSS"; // Payment Card Industry Data Security Standard

export type PiiSeverity = "low" | "medium" | "high" | "critical";

export interface PiiPattern {
  id: string;
  description: string;
  /** Must be pre-flagged global ("g"); no runtime recompilation. */
  regex: RegExp;
  severity: PiiSeverity;
  validate?: (matchedText: string) => boolean;
  /**
   * Which framework(s) this identifier is relevant to. A pattern can (and
   * often does) belong to more than one.
   */
  frameworks: ComplianceFramework[];
}

// --- Baseline: always active regardless of framework selection --------------
// Email is treated as personal data / PII across every major framework and
// has a very low false-positive rate, so it isn't gated behind a framework
// toggle at all — same behavior as before this file existed.
export const BASELINE_PII_PATTERNS: PiiPattern[] = [
  {
    id: "email-address",
    description: "Email address",
    regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    severity: "low",
    frameworks: [],
  },
];

// --- Framework-gated patterns -------------------------------------------------
export const FRAMEWORK_PII_PATTERNS: PiiPattern[] = [
  {
    id: "phone-number",
    description: "Phone number",
    regex: /\b\+?\d[\d\s()-]{7,}\d\b/g,
    severity: "low",
    // A 9-digit SSN written as XXX-XX-XXXX satisfies the loose character-
    // class regex above (11 chars total). Requiring 10+ actual digits
    // (the realistic minimum for a phone number with area/country code)
    // excludes that overlap without complicating the regex itself.
    validate: (matched) => matched.replace(/\D/g, "").length >= 10,
    // Telephone/fax numbers are explicit HIPAA Safe Harbor identifiers,
    // and personal info under GDPR and CCPA.
    frameworks: ["GDPR", "HIPAA", "CCPA"],
  },
  {
    id: "us-ssn",
    description: "US Social Security Number",
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    severity: "high",
    // SSN is explicit HIPAA Safe Harbor identifier #7 and a sensitive
    // identifier under most US state privacy/breach-notification law.
    frameworks: ["HIPAA", "CCPA"],
  },
  {
    id: "credit-card-number",
    description: "Credit card number (Luhn-validated)",
    regex: /\b(?:\d[ -]?){13,19}\b/g,
    severity: "high",
    validate: passesLuhnCheck,
    frameworks: ["PCI_DSS", "CCPA"],
  },
  {
    id: "ipv4-address",
    // Explicit HIPAA Safe Harbor identifier (#15); GDPR treats it as
    // personal data (Recital 30, CJEU Breyer); CCPA's "personal
    // information" definition explicitly includes network activity
    // identifiers.
    description: "IPv4 address (network identifier)",
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
    severity: "low",
    frameworks: ["GDPR", "HIPAA", "CCPA"],
  },
  {
    id: "date-of-birth",
    // Keyword-gated: DOB/birth date/born on + a date. HIPAA Safe Harbor
    // requires redacting all date elements tied to an individual more
    // granular than year.
    description: "Date of birth (matches DOB, birth date, born on + a date)",
    regex:
      /\b(?:DOB|date of birth|birth\s*date|born on)\s*[:\-]?\s*(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\d{4}-\d{2}-\d{2})\b/gi,
    severity: "high",
    frameworks: ["HIPAA", "GDPR"],
  },
  {
    id: "medical-record-number",
    description: "Medical/health record number",
    regex: /\b(?:MRN|medical record(?:\s+number)?)\s*[:#]?\s*\d{6,10}\b/gi,
    severity: "high",
    frameworks: ["HIPAA"],
  },
  {
    id: "medicare-beneficiary-id",
    // This is a loose 4-3-4 alphanumeric shape (e.g. 1EG4-TE5-MK73), not
    // the exact CMS per-position spec (which excludes ambiguous letters
    // like S/L/O/I/B/Z in specific positions). Verify against current CMS
    // documentation before relying on this for real detection — flagged
    // here rather than asserting false precision.
    description: "Medicare Beneficiary Identifier (MBI) — health insurance ID",
    regex: /\b[1-9][A-Z0-9]{3}-[A-Z0-9]{3}-[A-Z0-9]{4}\b/g,
    severity: "high",
    frameworks: ["HIPAA"],
  },
  {
    id: "us-bank-routing-number",
    // ABA checksum-validated: 3/7/1-weighted digit sum mod 10 == 0 — a
    // real, verifiable algorithm, unlike the MBI shape above.
    description: "US bank routing number (9-digit ABA number)",
    regex: /\b\d{9}\b/g,
    severity: "high",
    validate: passesAbaRoutingChecksum,
    frameworks: ["CCPA", "PCI_DSS"],
  },
  {
    id: "us-drivers-license-generic",
    // Format varies by state; this is a low-confidence heuristic
    // (requires an explicit "DL" or "driver's license" keyword nearby),
    // not an authoritative per-state validator.
    description: "US driver's license number (format varies by state)",
    regex: /\b(?:DL|driver'?s?\s*licen[cs]e)\s*[:#]?\s*[A-Z0-9]{6,12}\b/gi,
    severity: "medium",
    frameworks: ["CCPA"],
  },
];
