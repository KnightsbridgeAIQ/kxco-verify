# Changelog

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
