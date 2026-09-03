# Changelog

## 1.3.0

Additive. The library is byte-for-byte unchanged: same one dependency, same
offline behaviour, no notion of a chain anywhere in `src/`.

### A command line

`npx kxco-verify <url>` fetches and verifies an attestation, with `--file` for
a manifest you already have and `--json` for CI. Exit codes: 0 valid, 1 invalid
or revoked, 2 fetch or parse error, 3 rotated.

The default path contacts nothing but the site being checked. No KXCO server,
no licence, no account. That is what this package is for and it is not
changing.

### `--live`

Asks the KXCO key registry whether the signing kid is still active, after the
maths has passed. A signature made by a key revoked an hour ago is still a
perfectly valid signature, and no offline check can tell you otherwise.

It **fails closed**: an unreachable registry means not valid. A check that
could not run has not passed.

It needs `kxco-pq-network`, declared as an **optional** peer dependency so it
is not installed by default. Without it the flag prints what to install and
exits 2; everything else is unaffected. This is deliberate: making it a real
dependency would put a chain-aware package in the install path of a library
whose whole claim is that it has neither.

The registry is asked only once the signature has verified. A forged manifest
is a forged manifest whatever the registry says about the key it names, and
reporting it as a revocation would mislead.

## 1.2.1

Released to carry an npm provenance attestation. **No functional change**: no
source file is touched and the dependency set is identical to the previous
version.

Earlier releases of this package have no attestation, and provenance attaches to
a version rather than to a package, so it cannot be applied retroactively. The
publish workflow now declares `id-token: write`, publishes with `--provenance`
instead of `--no-provenance`, and authenticates through an npm Trusted Publisher
binding. Verify with `npm view kxco-verify dist.attestations`.

## 1.1.0 — 2026-07-22

Engine modernization. Public API unchanged; all 50 tests pass, including live
verification of the pinned attestation fixtures.

### Changed
- **`@noble/post-quantum` bumped `^0.2.1` → `^0.6.1`** (FIPS 203/204/205 final
  reference implementation). Absorbs the upstream breaking change: `ml_dsa65.verify`
  argument order is now `(signature, message, publicKey)`, and the subpath import
  requires the `.js` extension. Both are handled internally — `verifySignature()`
  behaves identically.
- `engines.node` raised to `>=20.19` to match the `@noble/post-quantum@0.6`
  requirement.
- `author` set to Shayne Heffernan and John Heffernan.

## 1.0.0 — 2026-05-24

Stable release.



## 0.1.3 — 2026-05-24

Maintenance release. No breaking changes.



## 0.1.2 — 2026-05-24

Maintenance release. No breaking changes.



## 0.1.1 — 2026-05-24

Maintenance release. No breaking changes.



All notable changes to this project will be documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project follows [Semantic Versioning](https://semver.org/).

## [0.1.0] â€” 2026-05-22

Initial release. Phase 1 of the [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) evolution brief.

### Added
- `verifyManifest(input)` â€” verify an attestation manifest object or JSON string. Returns the 3-state result envelope (`valid` / `invalid` / `error`).
- `verifyUrl(url, opts—)` â€” fetch and verify an attestation by URL. May additionally return `rotated` when the live well-known endpoint serves a different kid than the manifest declared.
- `parseManifest(input)` â€” typed-ish parser with byte-count sanity for ML-DSA-65 publicKey (1952 bytes) and signature (3309 bytes).
- `verifySignature(publicKey, message, signature)` â€” ML-DSA-65 (NIST FIPS 204) verification via `@noble/post-quantum`.
- `computeKid(publicKey)` â€” first 16 hex chars of SHA-256(rawPubkeyBytes). Matches the algorithm used by `kxco-post-quantum`'s `fingerprint()`.
- `getJsonBody(url, opts—)` â€” fetch helper with timeout (default 3000ms), max-byte cap (default 200KB), and SSRF-aware URL validation.
- Browser-safe implementation throughout â€” no `Buffer`, no `node:crypto`, no `process`. Uses `crypto.subtle` where available, falls back to `node:crypto` on Node 18.
- Live production fixtures captured in `fixtures/` for `chain.kxco.ai/wallet` and `www.target150.com`.
- Test suite: 50 tests, 97.5%+ line coverage, includes adversarial cases (signature tampering, kid mismatch, malformed JSON, byte-length attacks).
- Smoke script (`npm run smoke`) that exercises both production endpoints end-to-end.

### Known limitations (deliberately deferred to later phases)
- No KXCO-controlled key registry. Verification is a math claim only.
- No SLH-DSA-128s or hybrid envelopes â€” ML-DSA-65 only.
- No transparency log.
- The browser app at `verify.kxco.ai` is gated by CORS on the target site. Sites that don't serve `Access-Control-Allow-Origin: *` on their attestation endpoint require the "paste the JSON" fallback path.

### License
Apache 2.0. Independent of the (MIT-licensed) `kxco-post-quantum` signer.

[0.1.0]: https://github.com/JackKXCO/kxco-verify/releases/tag/v0.1.0
