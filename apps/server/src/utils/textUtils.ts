/**
 * Small, dependency-free text utilities used by the safety middleware's
 * evaluation pipeline. Kept deliberately simple (pure string/math ops) to
 * preserve the "lightweight" requirement — no ML, no external calls.
 */

/**
 * Normalizes text for prompt-injection scanning only. Deliberately NOT used
 * before secret/PII scanning, because those detectors rely on exact
 * character offsets for redaction — normalizing first could shift positions
 * or alter the literal secret text being redacted.
 *
 * - NFKC-normalizes Unicode (folds visually-similar/compatibility chars).
 * - Strips zero-width and bidi control characters commonly used to split up
 *   filtered phrases (e.g. "i\u200Bgnore previous instructions").
 * - Collapses repeated whitespace so padded-out phrases still match.
 */
export function normalizeForInjectionScan(input: string): string {
  return input
    .normalize("NFKC")
    .replace(/[\u200B-\u200F\u202A-\u202E\uFEFF]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Shannon entropy in bits/character. Used to suppress false positives on
 * generic/keyword-based secret rules (e.g. `password = "changeme"` has low
 * entropy and is very likely not a real leaked credential; a random 32-char
 * token has high entropy and likely is). This mirrors the entropy gate
 * Gitleaks applies to its own generic rules.
 */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;

  const frequencies = new Map<string, number>();
  for (const char of value) {
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of frequencies.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

/**
 * Luhn checksum, used to cheaply cut credit-card false positives (phone
 * numbers, order IDs, etc. rarely pass Luhn) without needing a real PAN
 * validation library.
 */
export function passesLuhnCheck(candidate: string): boolean {
  const digits = candidate.replace(/\D/g, "");
  if (digits.length < 12 || digits.length > 19) return false;

  let sum = 0;
  let shouldDouble = false;

  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let digit = Number(digits[i]);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }

  return sum % 10 === 0;
}
