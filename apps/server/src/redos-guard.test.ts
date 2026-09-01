import { describe, expect, it } from "vitest";
import { SECRET_PATTERNS } from "./patterns/secretPatterns.js";
import { PROMPT_INJECTION_PATTERNS } from "./patterns/promptInjectionPatterns.js";
import {
  BASELINE_PII_PATTERNS,
  FRAMEWORK_PII_PATTERNS,
} from "./patterns/compliancePatterns.js";
import { buildLearnedSecretPattern } from "./safety-middleware.js";

/*
 * This file exists specifically to catch a class of bug the rest of the
 * suite doesn't: catastrophic regex backtracking (ReDoS). Every pattern
 * here runs on every single message the middleware evaluates, so a single
 * badly-shaped regex is a real availability risk, not just a correctness
 * one — one crafted message could tie up the event loop indefinitely.
 *
 * Today's patterns were manually checked (structurally, and against
 * adversarial input) and found clean. That check was a one-off, done by a
 * person, outside CI. This file turns it into a permanent, automatic gate:
 * if a future pattern is added with a vulnerable shape, one of these two
 * tests fails immediately instead of the gap going unnoticed until
 * something in production hangs.
 *
 * This is the technical enforcement side of the growth policy documented
 * at the top of patterns/secretPatterns.ts: that policy tells a person
 * when a new regex is warranted versus when to extend the classifier
 * instead; this file is what actually catches it if a new regex slips
 * through with a bad shape regardless.
 */

// A representative learned pattern, built via the REAL construction
// function (not a hand-duplicated copy of its logic) — every declared
// "Run secret" name produces a pattern from this exact same template, so
// covering one representative case here covers the shape for all of them.
const representativeLearnedPattern = buildLearnedSecretPattern(
  "REPRESENTATIVE_LEARNED_SECRET_NAME",
  32,
);

const allPatterns = [
  ...SECRET_PATTERNS,
  ...PROMPT_INJECTION_PATTERNS,
  ...BASELINE_PII_PATTERNS,
  ...FRAMEWORK_PII_PATTERNS,
  representativeLearnedPattern,
];

describe("ReDoS regression gate", () => {
  it("no pattern contains a nested-unbounded-quantifier shape", () => {
    // The classic catastrophic-backtracking trigger: a quantified group
    // that itself contains another quantified, overlapping construct, with
    // no upper bound anywhere to cut the search space — e.g. (a+)+ or
    // (a|a)*. This is a structural heuristic, not a proof (static ReDoS
    // detection is a known-hard problem), so it's paired with the timing
    // test below rather than relied on alone.
    const nestedUnboundedQuantifier = /\([^)]*[+*][^)]*\)[+*]/;

    const flagged = allPatterns.filter((pattern) =>
      nestedUnboundedQuantifier.test(pattern.regex.source),
    );

    expect(
      flagged.map((p) => p.id),
      "Found pattern(s) with a nested-unbounded-quantifier shape — verify " +
        "manually whether they can catastrophically backtrack before merging.",
    ).toEqual([]);
  });

  it("every pattern completes well within budget against adversarial input", () => {
    // Shapes known to trigger backtracking blowups in vulnerable regexes:
    // long runs that almost-but-don't-quite match, long single-character
    // repeats, and large inputs mixing several character classes a pattern
    // might key on (letters, digits, punctuation, separators).
    const adversarialInputs = [
      "a".repeat(50_000),
      "A".repeat(50_000) + "!",
      "aB3".repeat(15_000),
      "=".repeat(20_000) + '"'.repeat(20_000),
      "-".repeat(30_000),
      ("word ".repeat(1) + "1").repeat(8_000),
    ];

    // Generous on purpose: this isn't a tight perf SLA, it's a tripwire for
    // genuinely pathological (exponential/high-polynomial) behavior, which
    // blows past this by orders of magnitude, not by a small margin.
    const budgetMs = 200;

    for (const pattern of allPatterns) {
      for (const input of adversarialInputs) {
        const start = performance.now();
        const matches = [...input.matchAll(pattern.regex)];
        const elapsed = performance.now() - start;

        expect(
          elapsed,
          `Pattern "${pattern.id}" took ${elapsed.toFixed(1)}ms against a ` +
            `${input.length}-char adversarial input (budget: ${budgetMs}ms). ` +
            `This usually means catastrophic backtracking, not just a slow regex.`,
        ).toBeLessThan(budgetMs);

        // Touch the result so the matcher can't be optimized away and so a
        // future refactor can't silently swap in a lazy/no-op stand-in.
        void matches.length;
      }
    }
  });
});
