import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import {
  createChallenge,
  createNonceStore,
  verifyChallenge,
  challengeMessage,
  REASONS,
  DEFAULT_TTL_SECONDS,
} from "../src/identity";
import type { Challenge } from "../src/identity";

const owner = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const other = privateKeyToAccount("0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a");

const NOW = 1792400000;
const fixedRandom = (n: number) => new Uint8Array(n).fill(7);

const build = (over: Partial<Parameters<typeof createChallenge>[0]> = {}) =>
  createChallenge({ did: "did:pkh:eip155:8453:0xaaa", listingId: "lax-ext-1", now: NOW, ...over }, fixedRandom);

const sign = (challenge: Challenge) => owner.signMessage({ message: challenge.message });

describe("createChallenge", () => {
  it("issues a deterministic nonce from the provided bytes", () => {
    const c = build();
    expect(c.nonce).toBe("07".repeat(16));
    expect(c.nonce).toHaveLength(32);
  });

  it("applies the default ttl", () => {
    const c = build();
    expect(c.expiresAt - c.issuedAt).toBe(DEFAULT_TTL_SECONDS);
  });

  it("applies a custom ttl and accepts a Date for now", () => {
    const c = build({ now: new Date(NOW * 1000 + 999), ttlSeconds: 60 });
    expect(c.issuedAt).toBe(NOW);
    expect(c.expiresAt).toBe(NOW + 60);
  });

  it("builds the message from its own fields", () => {
    const c = build();
    expect(c.message).toBe(challengeMessage(c.did, c.listingId, c.nonce, c.issuedAt, c.expiresAt));
    expect(c.message).toContain("Cerberus chamber 1");
  });

  it("refuses an empty did, an empty listing and a non positive ttl", () => {
    expect(() => build({ did: "  " })).toThrow(/did/);
    expect(() => build({ listingId: "" })).toThrow(/listingId/);
    expect(() => build({ ttlSeconds: 0 })).toThrow(/ttlSeconds/);
  });

  it("refuses a non finite now", () => {
    expect(() => build({ now: Number.NaN })).toThrow(/now/);
  });
});

describe("verifyChallenge", () => {
  it("accepts a valid signature from the owner", async () => {
    const c = build();
    const r = await verifyChallenge({ challenge: c, signature: await sign(c), ownerAddress: owner.address, now: NOW + 10 });
    expect(r).toEqual({ ok: true, reason: REASONS.ok, nonce: c.nonce });
  });

  it("accepts the owner address in a different case", async () => {
    const c = build();
    const r = await verifyChallenge({ challenge: c, signature: await sign(c), ownerAddress: owner.address.toUpperCase().replace("0X", "0x"), now: NOW + 10 });
    expect(r.ok).toBe(true);
  });

  it("rejects a signature from another signer", async () => {
    const c = build();
    const sig = await other.signMessage({ message: c.message });
    const r = await verifyChallenge({ challenge: c, signature: sig, ownerAddress: owner.address, now: NOW + 10 });
    expect(r.ok).toBe(false);
    expect(r.reason).toContain(REASONS.wrongSigner);
  });

  it("rejects an expired challenge", async () => {
    const c = build({ ttlSeconds: 30 });
    const r = await verifyChallenge({ challenge: c, signature: await sign(c), ownerAddress: owner.address, now: NOW + 31 });
    expect(r).toEqual({ ok: false, reason: REASONS.expired });
  });

  it("rejects a challenge issued in the future", async () => {
    const c = build();
    const r = await verifyChallenge({ challenge: c, signature: await sign(c), ownerAddress: owner.address, now: NOW - 1 });
    expect(r).toEqual({ ok: false, reason: REASONS.notYetValid });
  });

  it("rejects a replayed nonce from a Set and from an array", async () => {
    const c = build();
    const signature = await sign(c);
    const asSet = await verifyChallenge({ challenge: c, signature, ownerAddress: owner.address, now: NOW + 10, usedNonces: new Set([c.nonce]) });
    const asArray = await verifyChallenge({ challenge: c, signature, ownerAddress: owner.address, now: NOW + 10, usedNonces: [c.nonce] });
    expect(asSet.reason).toBe(REASONS.replayed);
    expect(asArray.reason).toBe(REASONS.replayed);
  });

  it("accepts a nonce that is not in the used list", async () => {
    const c = build();
    const r = await verifyChallenge({ challenge: c, signature: await sign(c), ownerAddress: owner.address, now: NOW + 10, usedNonces: new Set(["deadbeef"]) });
    expect(r.ok).toBe(true);
  });

  it("rejects a tampered did because the message no longer matches", async () => {
    const c = build();
    const signature = await sign(c);
    const tampered: Challenge = { ...c, did: "did:pkh:eip155:8453:0xbbb" };
    const r = await verifyChallenge({ challenge: tampered, signature, ownerAddress: owner.address, now: NOW + 10 });
    expect(r.reason).toBe(REASONS.tampered);
  });

  it("rejects a tampered expiresAt", async () => {
    const c = build();
    const tampered: Challenge = { ...c, expiresAt: c.expiresAt + 3600 };
    const r = await verifyChallenge({ challenge: tampered, signature: await sign(c), ownerAddress: owner.address, now: NOW + 10 });
    expect(r.reason).toBe(REASONS.tampered);
  });

  it("rejects a malformed challenge", async () => {
    const r = await verifyChallenge({ challenge: { ...build(), did: "" }, signature: "0x", ownerAddress: owner.address, now: NOW });
    expect(r.reason).toBe(REASONS.malformed);
    const r2 = await verifyChallenge({ challenge: null as unknown as Challenge, signature: "0x", ownerAddress: owner.address, now: NOW });
    expect(r2.reason).toBe(REASONS.malformed);
  });

  it("rejects a missing owner address", async () => {
    const c = build();
    const r = await verifyChallenge({ challenge: c, signature: await sign(c), ownerAddress: "", now: NOW + 10 });
    expect(r.reason).toBe(REASONS.wrongSigner);
  });

  it("rejects a signature of the wrong shape", async () => {
    const c = build();
    const r = await verifyChallenge({ challenge: c, signature: "0xdead", ownerAddress: owner.address, now: NOW + 10 });
    expect(r.reason).toBe(REASONS.badSignatureShape);
  });

  it("returns a typed reason when recovery throws", async () => {
    const c = build();
    const bad = "0x" + "11".repeat(65);
    const r = await verifyChallenge({ challenge: c, signature: bad, ownerAddress: owner.address, now: NOW + 10 });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe(REASONS.badSignature);
  });
});

describe("nonce source", () => {
  it("falls back to crypto.getRandomValues when no generator is injected", () => {
    const a = createChallenge({ did: "did:pkh:eip155:8453:0xaaa", listingId: "lax-ext-1", now: NOW });
    const b = createChallenge({ did: "did:pkh:eip155:8453:0xaaa", listingId: "lax-ext-1", now: NOW });
    expect(a.nonce).toHaveLength(32);
    expect(/^[0-9a-f]{32}$/.test(a.nonce)).toBe(true);
    expect(a.nonce).not.toBe(b.nonce);
  });
});

describe("signature presence", () => {
  it("rejects a missing signature before recovery", async () => {
    const c = build();
    const r = await verifyChallenge({ challenge: c, signature: undefined as unknown as string, ownerAddress: owner.address, now: NOW + 10 });
    expect(r.reason).toBe(REASONS.badSignatureShape);
  });
});

describe("createNonceStore", () => {
  it("holds nonces between requests and blocks a replay", async () => {
    const store = createNonceStore();
    const c = build();
    const signature = await sign(c);
    const first = await verifyChallenge({
      challenge: c, signature, ownerAddress: owner.address, now: NOW + 5,
    });
    expect(first.ok).toBe(true);
    store.add(first.nonce as string);
    expect(store.size()).toBe(1);
    // The verifier stays pure: it only refuses when the caller passes the guard.
    const unguarded = await verifyChallenge({
      challenge: c, signature, ownerAddress: owner.address, now: NOW + 5,
    });
    expect(unguarded.ok).toBe(true);
    const guarded = await verifyChallenge({
      challenge: c, signature, ownerAddress: owner.address, now: NOW + 5,
      usedNonces: [first.nonce as string],
    });
    expect(guarded.reason).toBe(REASONS.replayed);
  });

  it("accepts an initial iterable", () => {
    const store = createNonceStore(["a"]);
    expect(store.has("a")).toBe(true);
    expect(store.has("b")).toBe(false);
  });
});
