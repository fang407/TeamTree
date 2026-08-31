/**
 * Prompt-injection / jailbreak detection reference collection.
 *
 * There's no single canonical "gitleaks-for-injection" ruleset, but a small
 * number of open-source projects converge on the same heuristic categories:
 *
 *  - Vigil (deadbits/vigil-llm, YARA heuristics): "Instruction Bypass" and
 *    "System Instructions" categories for override/role-reassignment phrasing.
 *  - Rebuff (protectai/rebuff): keyword/heuristic pre-filter ahead of its
 *    vector-similarity and LLM checks.
 *  - LlamaFirewall / PromptGuard 2 (Meta): documents that jailbreaks are
 *    "explicit, repetitive, and pattern-rich" — i.e. good candidates for
 *    cheap pattern matching, unlike subtler goal-hijacking attacks.
 *  - garak (NVIDIA) probe taxonomy: used here only as a naming reference for
 *    attack categories, not imported as code.
 *
 * This file is a DATA collection, not logic. Treat it as a living
 * denylist: extend it as new phrasing shows up in logs, independent of
 * safety-middleware.ts.
 *
 * IMPORTANT (documented limitation, not solved here): regex/keyword matching
 * catches known, explicit phrasing. It will not reliably catch novel
 * paraphrases, non-English attacks, or indirect injection smuggled in via
 * retrieved documents/tool output rather than the user prompt itself. Treat
 * this as one cheap layer, not a complete defense — see README notes in the
 * middleware file.
 */

export type InjectionSeverity = "low" | "medium" | "high" | "critical";

export interface InjectionPattern {
  id: string;
  description: string;
  category:
    | "instruction_override"
    | "role_reassignment"
    | "prompt_exfiltration"
    | "delimiter_injection"
    | "destructive_command";
  /** Must be pre-flagged global ("g"); no runtime recompilation. */
  regex: RegExp;
  severity: InjectionSeverity;
}

export const PROMPT_INJECTION_PATTERNS: InjectionPattern[] = [
  {
    id: "safety-policy-bypass",
    description: "Attempt to disable or ignore safety rules or redaction",
    category: "instruction_override",
    regex: /\b(?:ignore|disable|turn\s+off|bypass|do\s+not\s+follow)\s+(?:all\s+|the\s+)?(?:safety\s+(?:rules?|checks?|filter)|redaction|security\s+(?:rules?|checks?))\b/gi,
    severity: "critical",
  },
  {
    id: "environment-secret-exfiltration",
    description: "Request to print environment variables or hidden values",
    category: "prompt_exfiltration",
    regex: /\b(?:print|show|display|output|dump|reveal)\s+(?:all\s+)?(?:environment\s+variables?|env\s+vars?|hidden\s+values?|secrets?|credentials?)\b/gi,
    severity: "high",
  },
  {
    id: "original-prompt-exfiltration",
    description: "Request to reveal the original or unredacted prompt or tool output",
    category: "prompt_exfiltration",
    regex: /\b(?:show|print|return|reveal|give\s+me)\s+(?:the\s+)?(?:original|raw|unredacted)\s+(?:prompt|request|tool\s+output|output)\b/gi,
    severity: "high",
  },
  {
    id: "reveal-developer-message",
    description: "Request to reveal developer or hidden application messages",
    category: "prompt_exfiltration",
    regex: /\b(?:show|print|return|reveal|repeat|display)\s+(?:me\s+)?(?:the\s+)?(?:developer\s+(?:message|prompt|instructions?)|hidden\s+(?:message|context)|application\s+instructions?)\b/gi,
    severity: "high",
  },
  {
    id: "reveal-tool-arguments",
    description: "Request to expose hidden tool arguments or internal tool data",
    category: "prompt_exfiltration",
    regex: /\b(?:show|print|return|reveal|dump|display)\s+(?:all\s+)?(?:hidden\s+)?(?:tool\s+(?:arguments?|parameters?|inputs?)|function\s+(?:arguments?|parameters?)|internal\s+tool\s+data)\b/gi,
    severity: "high",
  },
  {
    id: "reveal-conversation-history",
    description: "Request to expose hidden conversation or prior run history",
    category: "prompt_exfiltration",
    regex: /\b(?:show|print|return|reveal|dump|repeat)\s+(?:the\s+)?(?:full\s+)?(?:conversation\s+history|chat\s+history|prior\s+(?:messages?|conversation)|hidden\s+messages?)\b/gi,
    severity: "high",
  },
  {
    id: "fake-authority-claim",
    description: "Claim of administrator or developer approval used to bypass safeguards",
    category: "instruction_override",
    regex: /\b(?:the\s+)?(?:admin(?:istrator)?|developer|system\s+owner|security\s+team)\s+(?:has\s+)?(?:approved|authorized|允许|said)\s+(?:you\s+to\s+)?(?:ignore|disable|bypass|reveal|show|print)\b/gi,
    severity: "high",
  },
  {
    id: "user-text-as-system-instruction",
    description: "Attempt to make user-provided text act as a system instruction",
    category: "instruction_override",
    regex: /\b(?:treat|consider|regard)\s+(?:the\s+)?(?:user|following|next|quoted)\s+(?:text|message|content|block)\s+as\s+(?:a\s+)?(?:system|developer|administrator)\s+(?:message|instruction|command)\b/gi,
    severity: "high",
  },
  {
    id: "encoded-instruction-bypass",
    description: "Possible encoded or obfuscated instruction intended to bypass safeguards",
    category: "instruction_override",
    regex: /\b(?:decode\s+(?:this\s+)?(?:base\s*64|rot\s*13|hex)|(?:base\s*64|rot\s*13|hex)\s+(?:this|the\s+following))\s+(?:and\s+)?(?:follow|execute|obey)\s+(?:it|the\s+result)\b/gi,
    severity: "medium",
  },
  // --- Instruction override (Vigil: "Instruction Bypass") --------------------
  {
    id: "ignore-previous-instructions",
    description: "Explicit request to ignore/disregard prior instructions",
    category: "instruction_override",
    regex:
      /\b(?:ignore|disregard|forget|bypass)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:your|my|the|these|those)?\s*(?:previous|prior|earlier|above|preceding)\s+(?:instructions?|rules?|guidelines?|context|prompts?)\b/gi,
    severity: "critical",
  },
  {
    id: "new-instructions-injection",
    description: "Attempt to introduce a new authoritative instruction block",
    category: "instruction_override",
    regex: /\b(?:new|updated|real|actual)\s+instructions?\s*:/gi,
    severity: "high",
  },
  {
    id: "override-system-prompt",
    description: "Explicit request to override/disregard the system prompt",
    category: "instruction_override",
    regex:
      /\b(?:disregard|ignore|override)\s+(?:your\s+)?(?:system\s+prompt|system\s+message|guidelines|programming|training)\b/gi,
    severity: "critical",
  },

  // --- Role reassignment / jailbreak framing (Vigil: "System Instructions") --
  {
    id: "jailbreak-persona",
    description: "Request to adopt an unrestricted/jailbroken persona",
    category: "role_reassignment",
    regex:
      /\bact\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:dan\b|an?\s+unfiltered|a\s+jailbroken|an?\s+ai\s+with\s+no\s+restrictions)/gi,
    severity: "high",
  },
  {
    id: "developer-god-mode",
    description: "Claim of entering an unrestricted developer/god mode",
    category: "role_reassignment",
    regex:
      /\byou\s+(?:are\s+now|have\s+entered)\s+(?:in\s+)?(?:developer|god|jailbreak|unrestricted)\s+mode\b/gi,
    severity: "high",
  },
  {
    id: "no-restrictions-pretend",
    description: "Request to pretend restrictions/filters don't apply",
    category: "role_reassignment",
    regex:
      /\bpretend\s+(?:you\s+)?(?:have\s+no|there\s+(?:are|is)\s+no)\s+(?:restrictions|rules|guidelines|filters|limitations)\b/gi,
    severity: "high",
  },

  // --- Prompt / system-instruction exfiltration -------------------------------
  {
    id: "reveal-system-prompt",
    description: "Request to reveal hidden/system instructions",
    category: "prompt_exfiltration",
    regex:
      /\b(?:reveal|show|print|output|repeat)\s+(?:me\s+)?(?:your|the)\s+(?:system\s+prompt|initial\s+instructions|hidden\s+instructions)\b/gi,
    severity: "medium",
  },
  {
    id: "what-are-your-instructions",
    description: "Direct probing for original/system instructions",
    category: "prompt_exfiltration",
    regex: /\bwhat\s+(?:are|were)\s+your\s+(?:original\s+)?instructions\b/gi,
    severity: "medium",
  },

  // --- Delimiter / fake-role token injection ----------------------------------
  {
    id: "fake-role-delimiter",
    description: "Fabricated system/admin role delimiter tokens",
    category: "delimiter_injection",
    regex: /(?:\[\[|<\|)\s*(?:system|admin)\s*(?:\]\]|\|>)/gi,
    severity: "medium",
  },
  {
    id: "fake-end-of-prompt",
    description: "Fabricated 'end of prompt' marker to smuggle new context",
    category: "delimiter_injection",
    regex: /###\s*(?:end\s*of\s*(?:system\s*)?prompt|system|instruction)s?\s*###/gi,
    severity: "medium",
  },

  // --- Destructive / dangerous command requests -------------------------------
  {
    id: "delete-all-files",
    description: "Instruction to delete/wipe all files",
    category: "destructive_command",
    regex: /\b(?:delete|remove|wipe)\s+all\s+files?\b/gi,
    severity: "critical",
  },
  {
    id: "shell-rm-rf-root",
    description: "Destructive shell command targeting root/filesystem",
    category: "destructive_command",
    regex: /\brm\s+-rf\s+\/(?:\s|$)/gi,
    severity: "critical",
  },
  {
    id: "sql-drop-table",
    description: "Destructive SQL statement",
    category: "destructive_command",
    regex: /\bdrop\s+(?:table|database)\b/gi,
    severity: "high",
  },
  {
    id: "format-disk",
    description: "Instruction to format a disk/drive",
    category: "destructive_command",
    regex: /\bformat\s+(?:the\s+)?(?:disk|drive|hard\s*drive)\b/gi,
    severity: "high",
  },
];
