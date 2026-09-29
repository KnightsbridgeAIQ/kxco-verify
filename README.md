# kxco-verify

**Verify a KXCO post-quantum signature in any browser or terminal, from the artefact alone, with no KXCO server in the trust path.**

[![npm](https://img.shields.io/npm/v/kxco-verify?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-verify)
[![downloads](https://img.shields.io/npm/dm/kxco-verify?label=downloads&color=b0964f)](https://www.npmjs.com/package/kxco-verify)
[![NIST ACVP](https://img.shields.io/badge/NIST_ACVP-1,793_passed,_0_failed-2ea44f)](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md)
[![npm provenance](https://img.shields.io/badge/npm-provenance-2ea44f)](https://www.npmjs.com/package/kxco-verify)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-verify)](https://socket.dev/npm/package/kxco-verify)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-verify.svg)](https://nodejs.org)
[![verify.kxco.ai](https://img.shields.io/badge/verify.kxco.ai-live-22c55e)](https://verify.kxco.ai)

Standalone post-quantum credential and attestation verifier for KXCO ML-DSA-65 signed documents. One dependency, pinned exactly. Works in any modern browser and in Node.js 20.19 and later.

- **No KXCO server in the trust path.** `verifyManifest()` makes no network request at all, and `verifyUrl()` contacts only the attestation URL you pass and the key endpoint the manifest names.
- **Runs in the browser as shipped.** No `Buffer`, no `process` and SHA-256 from WebCrypto, which is how [verify.kxco.ai](https://verify.kxco.ai) checks a signature entirely in the tab.
- **Catches key rotation.** `verifyUrl()` compares the signing key with the one the site serves now and reports `rotated`, a state of its own, so a site mid-rotation is never mistaken for a forgery.
- **Live revocation on request.** `--live` asks the KXCO key registry whether the signing kid is still active, and fails closed.
- **Made for CI.** `npx kxco-verify <url>` exits 0 for valid, 1 for invalid or revoked, 2 when it cannot fetch or parse and 3 for rotated, with `--json` for machines.
- **Independent of the signer.** It calls the primitive directly and shares none of the KXCO signing code, so it can be audited on its own.
- **The primitive NIST's vectors pass.** Verification runs `@noble/post-quantum` 0.7.0, pinned exactly: the version [`kxco-post-quantum`](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md) holds to 1,793 NIST ACVP vectors passed, 0 failed, and 225 interoperability checks against liboqs, Bouncy Castle and the Python reference implementations, 0 failed.

**The migration has dates.**

- **NIST** published [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) in August 2024.
- **United States:** [Executive Order 14412](https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks), signed on 22 June 2026, moves federal high-value and high-impact systems to post-quantum key establishment by 31 December 2030 and to post-quantum signatures by 31 December 2031. [OMB M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf) requires PQC-agile libraries for all new applications.
- **United Kingdom:** the [NCSC](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines) sets 2028, 2031 and 2035 as its migration milestones.

[Quick start](#quick-start) · [Command line](#command-line) · [Browser usage](#browser-usage) · [For institutions](#for-institutions) · [Changelog](./CHANGELOG.md) · [kxco.ai](https://kxco.ai)

## When to use this

This package is for the **receiving end** of a KXCO signed attestation: anyone who needs to confirm that a signature is genuine without being a KXCO institution or running the full SDK.

Use this if you are:

- A regulator or auditor who received a signed document and needs to confirm it cryptographically
- A counterparty checking that an institution's attestation is valid before acting on it
- Building a browser-based verification UI (the public [verify.kxco.ai](https://verify.kxco.ai) runs this library entirely client-side)
- Writing a minimal verification script with no heavy dependencies
- An end user who wants to verify a credential independently, without trusting any intermediary server

To **sign** attestations, pick the signing package from [the KXCO post-quantum family](#the-kxco-post-quantum-family).

## Install

```bash
npm install kxco-verify
```

Node.js 20.19 and later. ESM only. One dependency, and no KXCO server in the trust path.

## Command line

```bash
npx kxco-verify https://www.target150.com/api/attestation
```

```
VALID  target150.com
  algorithm    ML-DSA-65
  kid          680f9af0bb44de3f

This means the site signed its own manifest with a key it published.
It is not an endorsement of the site, its owner, or its content.
```

`--file <path>` verifies a manifest you already have. `--json` prints a machine-readable result.

Exit codes are meant for CI: **0** valid, **1** invalid or revoked, **2** could not fetch or parse, **3** rotated.

### `--live`

A signature stays mathematically valid after its key is revoked, so `--live` asks the KXCO key registry whether the signing kid is still active:

```bash
npx kxco-verify https://example.com/.well-known/kxco-pq-attestation --live
```

```
VALID  example.com
  kid          aa29f37ab7f4b2cf
  registry     revoked
```

That exits **1**: the signature verifies, the registry reports the key revoked, and `--live` reports both facts.

`--live` **fails closed**: if the registry cannot be reached, the result is not valid, so a check that could not run never reads as a pass.

It uses [`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network), an **optional** peer dependency, so the default install stays at one dependency. Add it when you want the flag:

```bash
npm install kxco-pq-network
```

Registry base URL defaults to `https://chain.kxco.ai` and can be changed with `--registry`. A licence key, via `--licence` or `KXCO_LICENCE_KEY`, meters the reads; reads without one are allowed and rate-limited.

Everything above the `--live` heading works offline, forever, with no account and no licence.

## Quick start

```js
import { verifyUrl } from 'kxco-verify'

const result = await verifyUrl('https://www.target150.com/api/attestation')

console.log(result.state)         // 'valid' | 'rotated' | 'invalid' | 'error'
console.log(result.algorithm)     // 'ML-DSA-65'
console.log(result.manifestKid)   // '680f9af0bb44de3f'
console.log(result.site)          // 'target150.com'
console.log(result.deployment)    // { git_commit: '...', env: 'production', ... }
console.log(result.verifiedAtMs)  // timestamp (Date.now()) when verification completed
```

If you already have the manifest body in hand (from a prior fetch, a file, or user paste):

```js
import { verifyManifest } from 'kxco-verify'

const body = await fetch('https://www.target150.com/api/attestation').then(r => r.text())
const result = await verifyManifest(body)
```

### Result states

| `state` | Meaning |
|---|---|
| `"valid"` | Signature checks out against the manifest-declared key, and that key matches the live well-known endpoint. |
| `"rotated"` | Signature checks out, but the live well-known endpoint now serves a different key. The site is mid key-rotation: retry shortly. |
| `"invalid"` | The signature does not verify under the manifest-declared key, or the key identifier is inconsistent with the published key bytes. |
| `"error"` | The verifier could not run: network failure, malformed JSON, or unsupported algorithm. |

A `"valid"` result is a precise cryptographic statement: the site signed this manifest with the key it publishes. Who operates the site is a separate question, covered in [`docs/threat-model.md`](./docs/threat-model.md).

## For institutions

The cryptography is free under Apache-2.0, works offline and needs nothing from
KXCO, now or in ten years. What KXCO sells is the part that has to be operated:
an answer about the present.

| Service | What you get |
|---|---|
| Hosted key registry | Whether a key is active, revoked or rotated, answered at verification time |
| Meta-transaction relay | KXCO validates your signed intent, pays the gas and submits it, so you never hold a token or run a node |
| On-chain anchoring | A timestamp on Armature L1 that the chain itself has verified |
| Live revocation | `anchored+live` verification, which confirms the signing key is still trusted now |
| Support and SLA | Availability commitments, an escalation path and a named contact |

Priced in USD, per seat, per year. No tokens, no nodes and no wallets. The line
between free and paid is set out in
[LICENCE-PRODUCT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/LICENCE-PRODUCT.md).

**Talk to us: [admin@kxco.ai](mailto:admin@kxco.ai)** · [kxco.ai](https://kxco.ai)

## API

All exports are re-exported from the main entry point (`import ... from 'kxco-verify'`). Lower-level helpers are also available from their sub-paths.

### `verifyUrl(attestationUrl, opts?) → Promise<VerifyResult>`

Fetches the attestation at `attestationUrl`, verifies the ML-DSA-65 signature, then fetches the live well-known pubkey endpoint declared in the manifest (`publicKey.pinAt`) to detect key rotation. May return `"rotated"` if the live endpoint now serves a different key identifier.

```ts
verifyUrl(
  attestationUrl: string,
  opts?: {
    timeoutMs?:      number           // per request, default 3000
    maxBytes?:       number           // max response size to accept, default 200000
    fetchImpl?:      typeof fetch     // override the fetch implementation
    skipLivePubkey?: boolean          // skip rotation check (no live fetch)
  }
): Promise<VerifyResult>
```

### `verifyManifest(manifestBody) → Promise<VerifyResult>`

Verify a manifest you already have. Accepts a raw JSON string or a parsed object. Makes no network requests, so the result is `"valid"`, `"invalid"`, or `"error"`, and `"rotated"` belongs to `verifyUrl`.

```ts
verifyManifest(manifestBody: string | object): Promise<VerifyResult>
```

### `VerifyResult`

```ts
interface VerifyResult {
  state:           'valid' | 'rotated' | 'invalid' | 'error'
  algorithm?:      'ML-DSA-65'
  manifestKid?:    string                    // key identifier declared in the manifest
  livePubkeyKid?:  string                    // key identifier currently at the well-known endpoint
  site?:           string                    // site identifier declared by the manifest
  deployment?:     Record<string, unknown>   // opaque deployment metadata from the manifest
  manifestRaw?:    Record<string, unknown>   // full parsed manifest JSON
  error?:          VerifyResultError         // present when state is 'error', 'invalid', or 'rotated'
  attestationUrl?: string
  pubkeyUrl?:      string                    // well-known endpoint URL (when fetched)
  verifiedAtMs?:   number                    // Date.now() when verification completed
}

interface VerifyResultError {
  kind:     'parse' | 'fetch' | 'signature' | 'consistency' | 'rotation'
  code:     string
  message:  string
  soft?:    boolean   // true when the math succeeded but a soft check failed
}
```

### Low-level helpers

These are exported for callers who want to compose their own verification logic.

#### `parseManifest(input) → ParseResult`

Parse and validate a raw manifest body without running signature verification.

```ts
parseManifest(input: string | object): ParseResult
// ParseResult is { ok: true; manifest: ParsedManifest } | { ok: false; error: ParseError }
```

#### `verifySignature(publicKey, message, signature) → boolean`

Run ML-DSA-65 signature verification directly.

```ts
verifySignature(
  publicKey: Uint8Array | string,   // hex or bytes
  message:   Uint8Array | string,   // UTF-8 string or bytes
  signature: Uint8Array | string,   // hex or bytes
): boolean
```

#### `computeKid(publicKey) → Promise<string>`

Compute the KXCO key identifier: first 16 hex characters of SHA-256 of the raw public key bytes.

```ts
computeKid(publicKey: Uint8Array | string): Promise<string>
```

#### `getJsonBody(url, opts?) → Promise<FetchOk | FetchErr>`

Fetch a URL with timeout and size limits, returning the raw body string.

```ts
getJsonBody(url: string, opts?: GetJsonBodyOpts): Promise<FetchOk | FetchErr>
```

#### Utility: `hexToBytes`, `bytesToHex`, `hexEquals`

```ts
hexToBytes(hex: string): Uint8Array
bytesToHex(bytes: Uint8Array): string
hexEquals(a: string, b: string): boolean
```

## Browser usage

The library is browser-safe by construction. It uses no `Buffer` and no `process`, and takes SHA-256 from `crypto.subtle`, which every modern browser and Node.js 20.19 and later provide.

Use a bundler (Vite, esbuild, Rollup, webpack), or load as ESM via an import map that points each package at its folder:

```html
<script type="importmap">
{
  "imports": {
    "@noble/post-quantum/": "/lib/@noble/post-quantum/",
    "@noble/curves/":       "/lib/@noble/curves/",
    "@noble/hashes/":       "/lib/@noble/hashes/",
    "kxco-verify":          "/lib/kxco-verify/src/index.js"
  }
}
</script>
<script type="module">
  import { verifyUrl } from 'kxco-verify'
  const result = await verifyUrl('https://example.com/api/attestation')
  console.log(result.state)
</script>
```

This is how [verify.kxco.ai](https://verify.kxco.ai) works: the browser fetches the manifest directly and runs the maths in the tab, with no KXCO server in between.

## The KXCO post-quantum family

This is the receiving end: given an artefact and a public key, is the signature
valid. Browser-safe, offline, with no server in the path, which is what lets an
auditor confirm something years after it was issued. The rest of the family
covers the jobs around it:

| You need to | Install |
|---|---|
| Put the whole stack in one install | [`kxco-pq`](https://www.npmjs.com/package/kxco-pq) |
| Use ML-DSA, ML-KEM and SLH-DSA directly | [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) |
| Keep signing keys on the HSM you already run | [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) |
| Sign a document or record anyone can verify offline | [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) |
| Keep a tamper-evident audit trail | [`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit) |
| Verify a signature in a browser, with no server | [`kxco-verify`](https://www.npmjs.com/package/kxco-verify) |
| Issue institution identity credentials | [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) |
| Encrypt files and payloads to one or many recipients | [`kxco-pq-vault`](https://www.npmjs.com/package/kxco-pq-vault) |
| Encrypt Node streams and WebSockets | [`kxco-pq-tls`](https://www.npmjs.com/package/kxco-pq-tls) |
| Sign and verify webhooks | [`kxco-post-quantum-webhook`](https://www.npmjs.com/package/kxco-post-quantum-webhook) |
| Give an AI agent an identity a verified institution sponsors | [`kxco-pq-agent`](https://www.npmjs.com/package/kxco-pq-agent) |
| Have Armature L1 verify a signature in consensus | [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain) |
| Prove an envelope at three levels, offline to on-chain | [`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network) |
| Generate and rotate keys from a terminal | [`kxco-pq-cli`](https://www.npmjs.com/package/kxco-pq-cli) |
| Find quantum-vulnerable cryptography in a dependency tree | [`kxco-pq-scan`](https://www.npmjs.com/package/kxco-pq-scan) |
| Fail the build when code reaches past the wrapper | [`eslint-plugin-kxco-pq`](https://www.npmjs.com/package/eslint-plugin-kxco-pq) |

The verifier is architecturally independent of the signer: it calls the primitive directly and shares none of the KXCO signing code. That separation makes this package auditable in isolation: a change to the signing pipeline leaves the verifier untouched.

## Release integrity

Every release since 1.2.1 carries a SLSA provenance attestation tying the published tarball to
the commit and workflow that built it: verify with `npm audit signatures`, or read
it from `registry.npmjs.org/-/npm/v1/attestations/kxco-verify@<version>`. A CycloneDX
SBOM is published, from v1.2.1, as a GitHub Release asset at
`releases/download/v<version>/sbom.cyclonedx.json`, a permanent unauthenticated
URL. The one runtime dependency, `@noble/post-quantum`, is pinned to an exact
version, and every GitHub Action is pinned by commit SHA.

## Security

**ML-DSA-65** (NIST FIPS 204) via [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) 0.7.0, pinned exactly. No custom cryptography.

Evidenced, and reproducible on your own machine:

- **1,793 NIST ACVP vectors passed, 0 failed** across FIPS 203, 204 and 205 on `@noble/post-quantum` 0.7.0, pinned by digest, per [CONFORMANCE.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md). The other 310 are pairings the library refuses as weaker than the parameter set
- **225 interoperability checks passed, 0 failed**, against OpenSSL 3.5, liboqs, Bouncy Castle and dilithium-py/kyber-py, in both directions
- **SLSA provenance** on every release since 1.2.1: verify with `npm audit signatures`
- **CycloneDX SBOM** published with every release since 1.2.1

The audit history of every upstream library is recorded in [AUDIT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/AUDIT.md).

The library makes no outbound requests beyond the attestation URL you supply and the `pinAt` endpoint declared in the manifest. No data is sent to KXCO.

To report a vulnerability, open a [private security advisory](https://github.com/KnightsbridgeAIQ/kxco-verify/security/advisories/new) or email **john@knightsbridgelaw.com**. Acknowledgement within 2 business days, triage decision within 5. Full policy, including safe harbour for good-faith research: <https://kxco.ai/security>.

## License

Apache 2.0. See [LICENSE](./LICENSE).

## Maintainers

Shayne Heffernan and John Heffernan, [KXCO by Knightsbridge](https://kxco.ai)

[knightsbridgelaw.com](https://knightsbridgelaw.com) · [target150.com](https://target150.com) · [livetradingnews.com](https://livetradingnews.com)
