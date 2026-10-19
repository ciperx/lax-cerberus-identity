import { recoverMessageAddress, type Hex } from "viem";

export interface ChallengeInput {
  did: string;
  listingId: string;
  now: number | Date;
  ttlSeconds?: number;
}

export interface Challenge {
  did: string;
  listingId: string;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
  message: string;
}

export interface VerifyInput {
  challenge: Challenge;
  signature: string;
  ownerAddress: string;
  now: number | Date;
  usedNonces?: Set<string> | string[];
}

export interface VerifyResult {
  ok: boolean;
  reason: string;
  /** Present only on success, so the caller knows which nonce to consume. */
  nonce?: string;
}

export const DEFAULT_TTL_SECONDS = 300;
export const NONCE_BYTES = 16;

export const REASONS = {
  ok: "challenge accepted",
  malformed: "malformed challenge",
  expired: "challenge expired",
  notYetValid: "challenge issued in the future",
  tampered: "challenge message does not match its fields",
  replayed: "nonce already used",
  badSignature: "signature does not recover to the owner address",
  wrongSigner: "signature was produced by a different address",
  badSignatureShape: "signature is not a valid 65 byte hex string",
} as const;

const toSeconds = (value: number | Date): number => {
  const seconds = value instanceof Date ? Math.floor(value.getTime() / 1000) : Math.floor(value);
  if (!Number.isFinite(seconds)) throw new TypeError("now must be a finite time");
  return seconds;
};

const isNonEmpty = (value: unknown): value is string =>
  typeof value === "string" && value.trim().length > 0;

export function challengeMessage(
  did: string,
  listingId: string,
  nonce: string,
  issuedAt: number,
  expiresAt: number,
): string {
  return [
    "Cerberus chamber 1",
    "Identity of a listed LAX agent",
    `did: ${did}`,
    `listing: ${listingId}`,
    `nonce: ${nonce}`,
    `issued: ${issuedAt}`,
    `expires: ${expiresAt}`,
  ].join("\n");
}

export function createChallenge(input: ChallengeInput, randomBytes?: (n: number) => Uint8Array): Challenge {
  if (!isNonEmpty(input.did)) throw new TypeError("did must be a non empty string");
  if (!isNonEmpty(input.listingId)) throw new TypeError("listingId must be a non empty string");
  const issuedAt = toSeconds(input.now);
  const ttl = input.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  if (!Number.isFinite(ttl) || ttl <= 0) throw new TypeError("ttlSeconds must be positive");
  const expiresAt = issuedAt + Math.floor(ttl);

  const bytes =
    randomBytes?.(NONCE_BYTES) ??
    globalThis.crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const nonce = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return {
    did: input.did,
    listingId: input.listingId,
    nonce,
    issuedAt,
    expiresAt,
    message: challengeMessage(input.did, input.listingId, nonce, issuedAt, expiresAt),
  };
}

export async function verifyChallenge(input: VerifyInput): Promise<VerifyResult> {
  const challenge = input.challenge;
  if (
    !challenge ||
    !isNonEmpty(challenge.did) ||
    !isNonEmpty(challenge.listingId) ||
    !isNonEmpty(challenge.nonce) ||
    !isNonEmpty(challenge.message) ||
    !Number.isFinite(challenge.issuedAt) ||
    !Number.isFinite(challenge.expiresAt)
  ) {
    return { ok: false, reason: REASONS.malformed };
  }

  const now = toSeconds(input.now);
  if (challenge.expiresAt <= now) return { ok: false, reason: REASONS.expired };
  if (challenge.issuedAt > now) return { ok: false, reason: REASONS.notYetValid };

  const expected = challengeMessage(
    challenge.did,
    challenge.listingId,
    challenge.nonce,
    challenge.issuedAt,
    challenge.expiresAt,
  );
  if (expected !== challenge.message) return { ok: false, reason: REASONS.tampered };

  const used = input.usedNonces;
  if (used) {
    const seen = used instanceof Set ? used.has(challenge.nonce) : used.includes(challenge.nonce);
    if (seen) return { ok: false, reason: REASONS.replayed };
  }

  if (!isNonEmpty(input.ownerAddress)) {
    return { ok: false, reason: REASONS.wrongSigner };
  }
  if (!/^0x[0-9a-fA-F]{130}$/.test(input.signature ?? "")) {
    return { ok: false, reason: REASONS.badSignatureShape };
  }

  let recovered: string;
  try {
    recovered = await recoverMessageAddress({
      message: challenge.message,
      signature: input.signature as Hex,
    });
  } catch {
    return { ok: false, reason: REASONS.badSignature };
  }

  if (recovered.toLowerCase() !== input.ownerAddress.toLowerCase()) {
    return {
      ok: false,
      reason: `${REASONS.wrongSigner}: recovered ${recovered}`,
    };
  }
  return { ok: true, reason: REASONS.ok, nonce: challenge.nonce };
}

export interface NonceStore {
  has: (nonce: string) => boolean;
  add: (nonce: string) => void;
  size: () => number;
}

/**
 * A tiny in-memory guard so a server can actually use the replay check.
 *
 * The verifier stays pure and only reads; this is the piece a caller needs to
 * hold the nonces between requests. For more than one process, back it with a
 * database that has a unique constraint on the nonce.
 */
export function createNonceStore(initial: Iterable<string> = []): NonceStore {
  const seen = new Set<string>(initial);
  return {
    has: (nonce) => seen.has(nonce),
    add: (nonce) => {
      seen.add(nonce);
    },
    size: () => seen.size,
  };
}
