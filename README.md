# kxco-verify

[![npm](https://img.shields.io/npm/v/kxco-verify?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-verify)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-verify)](https://socket.dev/npm/package/kxco-verify)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-verify.svg)](https://nodejs.org)
[![verify.kxco.ai](https://img.shields.io/badge/verify.kxco.ai-live-22c55e)](https://verify.kxco.ai)

Standalone post-quantum credential and attestation verifier for KXCO ML-DSA-65 signed documents. Zero heavy dependencies. Works in any modern browser and Node 18+.

---

## When to use this

This package is for the **receiving end** of a KXCO signed attestation — anyone who needs to confirm that a signature is genuine without being a KXCO institution or running the full SDK.

Use this if you are:

- A regulator or auditor who received a signed document and needs to confirm it cryptographically
- A counterparty checking that an institution's attestation is valid before acting on it
- Building a browser-based verification UI (the public [verify.kxco.ai](https://verify.kxco.ai) runs this library entirely client-side)
- Writing a minimal verification script with no heavy dependencies
- An end user who wants to verify a credential independently, without trusting any intermediary server

If you need to **sign** attestations, see the packages listed under [Part of the KXCO stack](#part-of-the-kxco-stack).

---

## Install

```bash
npm install kxco-verify
```

Node 18+. ESM only.

---

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

const body = await fetch('https://example.com/api/attestation').then(r => r.text())
const result = await verifyManifest(body)
```

### Result states

| `state` | Meaning |
|---|---|
| `"valid"` | Signature checks out against the manifest-declared key, and that key matches the live well-known endpoint. |
| `"rotated"` | Signature checks out, but the live well-known endpoint now serves a different key. The site is mid key-rotation — retry shortly. |
| `"invalid"` | The signature does not verify under the manifest-declared key, or the key identifier is inconsistent with the published key bytes. |
| `"error"` | The verifier could not run: network failure, malformed JSON, or unsupported algorithm. |

A `"valid"` result means the signature math checks out. It does not mean KXCO has vetted the site, its operator, or its content. See [`docs/threat-model.md`](./docs/threat-model.md).

---

## API

All exports are re-exported from the main entry point (`import ... from 'kxco-verify'`). Lower-level helpers are also available from their sub-paths.

### `verifyUrl(attestationUrl, opts?) → Promise<VerifyResult>`

Fetches the attestation at `attestationUrl`, verifies the ML-DSA-65 signature, then fetches the live well-known pubkey endpoint declared in the manifest (`publicKey.pinAt`) to detect key rotation. May return `"rotated"` if the live endpoint now serves a different key identifier.

```ts
verifyUrl(
  attestationUrl: string,
  opts?: {
    timeoutMs?:      number           // default: no timeout
    maxBytes?:       number           // max response size to accept
    fetchImpl?:      typeof fetch     // override the fetch implementation
    skipLivePubkey?: boolean          // skip rotation check (no live fetch)
  }
): Promise<VerifyResult>
```

### `verifyManifest(manifestBody) → Promise<VerifyResult>`

Verify a manifest you already have. Accepts a raw JSON string or a parsed object. Does not make any network requests — so the result is `"valid"`, `"invalid"`, or `"error"` only, never `"rotated"`.

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

---

## Browser usage

The library is browser-safe by construction. It uses no `Buffer`, no `node:crypto`, and no `process`. SHA-256 is taken from `crypto.subtle` where available (every modern browser and Node 20+), with a `node:crypto` fallback on Node 18.

Use a bundler (Vite, esbuild, Rollup, webpack), or load as ESM via an import map:

```html
<script type="importmap">
{
  "imports": {
    "@noble/post-quantum/ml-dsa": "/lib/@noble/post-quantum/ml-dsa.js",
    "kxco-verify":                "/lib/kxco-verify/src/index.js"
  }
}
</script>
<script type="module">
  import { verifyUrl } from 'kxco-verify'
  const result = await verifyUrl('https://example.com/api/attestation')
  console.log(result.state)
</script>
```

This is how [verify.kxco.ai](https://verify.kxco.ai) works — no server receives your request; verification runs entirely in the browser.

---

## What this does NOT do

- **Cannot sign.** To produce ML-DSA-65 attestations, use [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-post-quantum) or `kxco-pq-attest`.
- **Cannot issue credentials.** Credential issuance — including KYC-backed identity documents — is handled by the full KXCO SDK and identity pipeline, not this package.
- **Not a full identity client.** This package verifies one thing: whether a given ML-DSA-65 signature is mathematically valid and matches the published key. It has no concept of users, sessions, or identity records.
- **No key registry.** There is no mapping from domain to approved key identifier. Anyone can generate an ML-DSA-65 keypair and publish a self-signed manifest; this library will mark it `"valid"`. A `"valid"` result is a math claim, not an endorsement.
- **ML-DSA-65 only.** SLH-DSA-128s and hybrid envelopes are not supported in this release.

---

## Part of the KXCO stack

This package is the receiving end of the KXCO post-quantum signing pipeline.

| Role | Package |
|---|---|
| Sign and attest deployments | [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) |
| Issue PQ-signed credentials | `kxco-pq-attest` |
| Agent-level signing and policy | `kxco-pq-agent` |
| **Verify any of the above** | **`kxco-verify`** (this package) |
| Public web verifier | [verify.kxco.ai](https://verify.kxco.ai) |

The verifier is architecturally independent of the signer — the two share no code. That separation makes this package auditable in isolation: a change to the signing pipeline cannot influence the verifier's behaviour.

---

## Security

Signature verification uses [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) ML-DSA-65, independently audited by Cure53 (2024) with no transitive dependencies. The library makes no outbound requests beyond the attestation URL you supply and the `pinAt` endpoint declared in the manifest. No data is sent to KXCO.

To report a vulnerability, open a [private security advisory](https://github.com/KnightsbridgeAIQ/kxco-verify/security/advisories/new) or email **security@kxco.ai**.

---

## License

Apache 2.0 — see [LICENSE](./LICENSE).

---

## Maintainers

Shayne Heffernan and John Heffernan — [KXCO by Knightsbridge](https://kxco.ai)

[knightsbridgelaw.com](https://knightsbridgelaw.com) · [target150.com](https://target150.com) · [livetradingnews.com](https://livetradingnews.com)
