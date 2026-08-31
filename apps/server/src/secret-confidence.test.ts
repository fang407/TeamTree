import { describe, expect, it } from "vitest";
import { secretConfidence, TRAINED_SECRET_LOGIT_MODEL } from "./secret-confidence.js";

/*
 * This file has two jobs, kept deliberately separate:
 *
 * 1. DRIFT GATEKEEPER — exact reference scores for a fixed set of inputs.
 *    If anyone edits TRAINED_SECRET_LOGIT_MODEL's coefficients (retraining,
 *    a typo, a copy-paste from a different run of the training script),
 *    these numbers move and the test fails. That's the point: a silent
 *    coefficient change should never ship unnoticed. If a retrain is
 *    genuinely intentional, these reference values need a conscious,
 *    reviewed update — not an accidental one.
 *
 * 2. BEHAVIORAL PROPERTIES — assertions that don't depend on the exact
 *    coefficients, so they keep working across a legitimate retrain and
 *    catch a different class of bug (e.g. the ordering logic itself
 *    breaking, independent of what the weights are).
 *
 * Reference values below were computed by calling secretConfidence()
 * directly against the code as it exists today, not hand-derived — see
 * commit history for how they were produced if they ever need updating.
 */

describe("secretConfidence — drift gatekeeper (exact reference values)", () => {
  it("scores a UUID at exactly 0", () => {
    expect(secretConfidence("550e8400-e29b-41d4-a716-446655440000")).toBe(0);
  });

  it("scores a SHA-1-shaped hex digest at exactly 0", () => {
    expect(
      secretConfidence("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"),
    ).toBe(0);
  });

  it("matches the reference score for a low-entropy plain word", () => {
    expect(secretConfidence("changeme")).toBeCloseTo(0.22721472873413626, 9);
  });

  it("matches the reference score for high-entropy text with no known prefix", () => {
    // Deliberately includes an underscore so this does NOT also satisfy
    // the ordinary-Base64 shape check below — keeps this case isolated to
    // just the entropy/length/mixed-class features.
    expect(secretConfidence("aB3dE5_G7hJ9kL2mN4pQ7rS9")).toBeCloseTo(
      0.2873818481693651,
      9,
    );
  });

  it("matches the reference score for the same text with a known secret prefix", () => {
    expect(secretConfidence("sk-aB3dE5fG7hJ9kL2mN4pQ7rS9")).toBeCloseTo(
      0.31526748211643857,
      9,
    );
  });

  it("matches the reference score for ordinary-looking Base64 with no known prefix", () => {
    // This is the counter-intuitive case worth calling out explicitly:
    // this scores LOWER than "changeme" above, because it also happens to
    // satisfy the ordinary-Base64 shape check (24+ chars, multiple of 4,
    // base64 alphabet), which applies a 0.2x suppression multiplier.
    // That's intentional (common non-secret identifiers are base64-shaped),
    // but it's exactly the kind of behavior a silent coefficient or
    // suppression-logic change could break without anyone noticing.
    expect(
      secretConfidence("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="),
    ).toBeCloseTo(0.16729876423033027, 9);
  });

  it("matches the reference score for Base64-shaped text WITH a known prefix", () => {
    // A known prefix (AKIA here) should override the Base64 suppression —
    // this must score high, not suppressed like the case above.
    expect(
      secretConfidence("AKIAQUJDREVGR0hJSktMTU5PUFFSU1RVVldY"),
    ).toBeCloseTo(0.8529725691831248, 9);
  });
});

describe("secretConfidence — behavioral properties (survive a legitimate retrain)", () => {
  it("a known secret prefix increases the score", () => {
    const withoutPrefix = secretConfidence("aB3dE5fG7hJ9kL2mN4pQ7rS9tU1v");
    const withPrefix = secretConfidence("sk-aB3dE5fG7hJ9kL2mN4pQ7rS9tU1v");
    expect(withPrefix).toBeGreaterThan(withoutPrefix);
  });

  it("mixing upper/lower/digit classes increases the score over a single-class string of the same length", () => {
    const singleClass = secretConfidence("abcdefghijklmnopqrstuvwx"); // lowercase only
    const allThreeClasses = secretConfidence("Abcdefghijklmnopqrstuvw1"); // adds one upper, one digit
    expect(allThreeClasses).toBeGreaterThan(singleClass);
  });

  it("every UUID-shaped string scores exactly 0, regardless of content", () => {
    const uuids = [
      "00000000-0000-1000-8000-000000000000",
      "ffffffff-ffff-4fff-bfff-ffffffffffff",
      "12345678-1234-5234-9234-123456789012",
    ];
    for (const uuid of uuids) {
      expect(secretConfidence(uuid)).toBe(0);
    }
  });

  it("every hex-digest-shaped string (MD5/SHA-1/SHA-256 length) scores exactly 0", () => {
    const digests = [
      "d41d8cd98f00b204e9800998ecf8427e", // 32 hex chars (MD5-length)
      "da39a3ee5e6b4b0d3255bfef95601890afd80709", // 40 hex chars (SHA-1-length)
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // 64 (SHA-256-length)
    ];
    for (const digest of digests) {
      expect(secretConfidence(digest)).toBe(0);
    }
  });

  it("confidence is always within [0, 1]", () => {
    const samples = [
      "",
      "a",
      "changeme",
      "sk-" + "a".repeat(100),
      "!!!!!!!!!!!!!!!!!!!!!!!!",
      "1234567890123456789012345678901234567890",
    ];
    for (const sample of samples) {
      const score = secretConfidence(sample);
      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(1);
    }
  });

  it("SURPRISING, VERIFIED QUIRK: higher entropy alone does not increase confidence in this trained model", () => {
    // The trained entropy coefficient is negative (see
    // TRAINED_SECRET_LOGIT_MODEL.entropy above). Counter-intuitively, that
    // means a more repetitive, LOWER-entropy string can score higher than a
    // genuinely random one, once length/mixed-class/prefix are held equal.
    // This is documented here, verified against real output, specifically
    // so nobody "fixes" this as a bug during a refactor without realizing
    // it reflects the actual trained coefficients (whether or not that
    // reflects a real pattern in the training data is a question for
    // retraining, not for this test to answer).
    const lowEntropyRepetitive = secretConfidence("AbAbAbAbAbAbAbAbAbAbAbA1");
    const higherEntropyVaried = secretConfidence("AbC3dEfG7hJ9kLmN4pQrStU1");
    expect(lowEntropyRepetitive).toBeGreaterThan(higherEntropyVaried);
  });
});

describe("secretConfidence — documents an implementation detail", () => {
  it("the uuid and hexDigest model coefficients are currently unreachable", () => {
    // UUID/digest inputs return 0 via an early return, BEFORE the logit
    // (which is where these two coefficients are used) is ever computed.
    // That means TRAINED_SECRET_LOGIT_MODEL.uuid and .hexDigest can never
    // actually influence a real score today — changing either has zero
    // effect on any input. This isn't necessarily a bug (the early return
    // may be an intentional, stronger override), but it's worth stating
    // explicitly rather than leaving it as an easy-to-miss implication of
    // the control flow. If the early return is ever removed so these
    // coefficients become reachable, this test should be revisited.
    const withRealCoefficients = secretConfidence(
      "550e8400-e29b-41d4-a716-446655440000",
    );

    expect(TRAINED_SECRET_LOGIT_MODEL.uuid).not.toBe(0);
    expect(TRAINED_SECRET_LOGIT_MODEL.hexDigest).not.toBe(0);
    expect(withRealCoefficients).toBe(0);
  });
});
