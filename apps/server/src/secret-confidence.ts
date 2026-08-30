import { shannonEntropy } from "./utils/textUtils.js";

/**
 * Numeric artefacts from the offline CredData logistic-regression training
 * script. No training examples or credentials are shipped at runtime.
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

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX_DIGEST = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i;

/**
 * Returns an offline confidence score for a token found in a credential
 * assignment. UUIDs, Git-style digests, and ordinary Base64 are deliberately
 * suppressed because they are common non-secret identifiers.
 */
export function secretConfidence(candidate: string): number {
  const compact = candidate.replace(/[\s-]/g, "");
  const isUuid = UUID.test(candidate);
  const isDigest = HEX_DIGEST.test(compact);
  const isBase64 = isOrdinaryBase64(compact);

  if (isUuid || isDigest) return 0;

  const entropy = Math.min(shannonEntropy(compact), 6) / 6;
  const length = Math.min(compact.length, 128) / 128;
  const mixedClasses = Number(
    /[a-z]/.test(compact) && /[A-Z]/.test(compact) && /\d/.test(compact),
  );
  const knownSecretPrefix = Number(
    /^(?:sk|ghp|github_pat|AKIA|xox[baprs])-?/i.test(compact),
  );

  const logit =
    TRAINED_SECRET_LOGIT_MODEL.bias +
    TRAINED_SECRET_LOGIT_MODEL.entropy * entropy +
    TRAINED_SECRET_LOGIT_MODEL.length * length +
    TRAINED_SECRET_LOGIT_MODEL.mixedClasses * mixedClasses +
    TRAINED_SECRET_LOGIT_MODEL.knownSecretPrefix * knownSecretPrefix +
    TRAINED_SECRET_LOGIT_MODEL.uuid * Number(isUuid) +
    TRAINED_SECRET_LOGIT_MODEL.hexDigest * Number(isDigest) +
    TRAINED_SECRET_LOGIT_MODEL.ordinaryBase64 * Number(isBase64);
  const confidence = 1 / (1 + Math.exp(-logit));

  return isBase64 && !knownSecretPrefix ? confidence * 0.2 : confidence;
}

function isOrdinaryBase64(value: string): boolean {
  return value.length >= 24 && value.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(value);
}
