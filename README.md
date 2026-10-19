# lax-cerberus-identity

Cerberus chamber 1: issue a challenge for a listed LAX agent, then verify the EIP-191 signature of the listing owner.

`createChallenge({ did, listingId, now, ttlSeconds? }) -> Challenge`
`verifyChallenge({ challenge, signature, ownerAddress, now, usedNonces? }) -> { ok, reason }`

## Install

```bash
npm install
npm test
npm run coverage
npm run build
```

## Use

```ts
import { createChallenge, verifyChallenge } from "lax-cerberus-identity";

const challenge = createChallenge({
  did: "did:pkh:eip155:8453:0x4c72...",
  listingId: "lax-ext-09a02a90e441",
  now: Date.now() / 1000,
  ttlSeconds: 300,
});

// owner signs challenge.message with personal_sign
const result = await verifyChallenge({
  challenge,
  signature: "0x...",
  ownerAddress: "0x4c72...",
  now: Date.now() / 1000,
  usedNonces,
});
```

## Guarantees

- **Expiry.** A challenge past `expiresAt` is refused with `challenge expired`. A challenge with `issuedAt` in the future is refused, so a skewed signer cannot mint a long lived one.
- **Replay protection.** A nonce already in the caller's set is refused with `nonce already used`. The store stays with the caller, so nothing here mutates shared state.
- **Tamper detection.** The message is rebuilt from the fields and compared, so changing the did or the expiry after issuance fails with `challenge message does not match its fields` even when the signature is genuine.
- **Signer binding.** Recovery is compared case insensitively against `ownerAddress`, so a checksummed or upper case address verifies.
- **Typed refusals.** Every failure returns `{ ok: false, reason }`, never a throw, so a caller can branch on the reason string.
- **Deterministic nonce in tests.** The generator is injectable, so a suite can pin the nonce, while production falls back to `crypto.getRandomValues`.

## Coverage

```
All files    |    100 |    100 |     100 |    100
```

100 percent statements, branches, functions and lines, measured with `vitest run --coverage` (v8). 21 tests.

## Mutation check

Removing the expiry branch fails one test, and changing the digest path in the sibling package fails two. Both were verified by mutation before pushing.

## Files

- `src/identity.ts`, types, the reason table, `challengeMessage`, the pure `createChallenge`, the async `verifyChallenge`.
- `test/identity.test.ts`, 21 tests over issue, verify, tamper, replay, expiry, future issue, shape and recovery failure.

## Why viem

viem is the Kognai stack. `recoverMessageAddress` is the same primitive the registry uses, so a verifier that accepts here accepts there.

## Licence

MIT.
