# kxco-verify

[![npm](https://img.shields.io/npm/v/kxco-verify?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-verify)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![verify.kxco.ai](https://img.shields.io/badge/verify.kxco.ai-live-22c55e)](https://verify.kxco.ai)

**Independent, browser-safe verifier for post-quantum signed deploy attestations** produced by sites using [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum).

Zero runtime dependencies beyond [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum). Apache 2.0. Works the same in Node 18+ and in any modern browser — the library never imports anything Node-specific. The public [`verify.kxco.ai`](https://verify.kxco.ai) web app runs this exact library entirely client-side; nothing is sent to a KXCO server.

> **Read this before you use the result.** A `"valid"` result means the signature math checks out against the public key the site itself declared, AND that key currently matches the live well-known endpoint. **It does not mean KXCO has vetted the site, its operator, or its content.** A self-signed attestation from a brand-new domain looks the same as one from a real institution — that's the point of cryptography, not a bug in the verifier. See [`docs/threat-model.md`](./docs/threat-model.md) for what is and isn't proven.

---

## Install

```bash
npm install kxco-verify
```

Node ≥18. ESM only.

## Quick start

### Verify a URL

```js
import { verifyUrl } from 'kxco-verify'

const r = await verifyUrl('https://www.target150.com/api/attestation')

console.log(r.state)         // 'valid' | 'rotated' | 'invalid' | 'error'
console.log(r.algorithm)     // 'ML-DSA-65'
console.log(r.manifestKid)   // '680f9af0bb44de3f'
console.log(r.deployment)    // { git_commit: '...', env: 'production', ... }
```

### Verify a manifest you already have

```js
import { verifyManifest } from 'kxco-verify'

const body = await fetch('https://www.target150.com/api/attestation').then(r => r.text())
const r    = await verifyManifest(body)
```

### CLI smoke against the production endpoints

```bash
npx kxco-verify-smoke
# or, if cloned locally:
npm run smoke
```

---

## The 3-state result

This is the single most important thing to understand before consuming this library.

| `state` | What it means | What it does not mean |
|---|---|---|
| `"valid"`   | Signature mathematically checks out against the manifest-declared key, AND that key matches the live `pinAt` well-known endpoint. | That the site is trustworthy, that KXCO endorses it, or that its content is what it claims to be. |
| `"rotated"` | Signature checks out against the kid the manifest declared, but the well-known endpoint now serves a different kid. The site is mid key-rotation. Retry shortly. | That the site is compromised. |
| `"invalid"` | The signature does NOT verify under the manifest's declared key, OR the kid does not match SHA-256 of the published pubkey bytes. | Necessarily that the site is malicious — could also be a misconfigured signer or tampering in flight. |
| `"error"`   | The verifier could not run (network failure, malformed JSON, unsupported algorithm). | That the signature is invalid. |

The full shape returned by `verifyUrl` / `verifyManifest` is documented in [`src/index.d.ts`](./src/index.d.ts).

---

## What the library does NOT do (yet)

Tracked for later phases of [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum):

- **No KXCO-controlled key registry.** There is no mapping from `domain → approved kid`. Anyone can generate an ML-DSA-65 keypair in 30 seconds and publish a self-signed manifest; this library will mark it `"valid"`. That is intentional for this release — verification is a math claim, not an endorsement. Future phases will add a registry; the verifier will then surface registry-status alongside the math result.
- **No SLH-DSA-128s or hybrid envelopes.** ML-DSA-65 (NIST FIPS 204) only.
- **No transparency log.** Whether a given attestation has been publicly seen before is not tracked here.

If your threat model requires any of the above, do not call a `"valid"` result a "trust verdict" in your UI without your own additional checks.

---

## Browser usage

The library is browser-safe by construction — no `Buffer`, no `node:crypto`, no `process`. SHA-256 is taken from `crypto.subtle` where available (every browser, Node 20+) and falls back to `node:crypto` on Node 18.

Use a bundler (Vite, esbuild, Rollup, webpack) or load as ESM directly via an import map:

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
  const r = await verifyUrl('https://example.com/api/attestation')
  console.log(r.state)
</script>
```

This is exactly what [`verify.kxco.ai`](https://verify.kxco.ai) does.

---

## Manifest shape

The verifier accepts the manifest shape produced by `kxco-post-quantum` since v1.0.x. The reference document is [`docs/verification.md`](./docs/verification.md). In brief:

```json
{
  "manifest": {
    "site": "example.com",
    "alg":  "ML-DSA-65",
    "spec": "NIST FIPS 204",
    "kid":  "<16 hex chars>",
    "deployment": { "<opaque-site-defined-fields>": "..." },
    "msgFormat":  "<template describing what was signed>"
  },
  "signedMessage": "<the actual bytes that were signed, as a string>",
  "signature": { "alg": "ML-DSA-65", "encoding": "hex", "value": "<6618 hex chars>" },
  "publicKey": {
    "alg": "ML-DSA-65", "encoding": "hex", "value": "<3904 hex chars>",
    "kid": "<same as manifest.kid>",
    "pinAt": "<relative URL of the live well-known pubkey endpoint>"
  }
}
```

Two live, real-world examples ship in [`fixtures/`](./fixtures):
- `wallet-attestation.json`    — `https://chain.kxco.ai/wallet/api/.well-known/kxco-pq-attestation`
- `target150-attestation.json` — `https://www.target150.com/api/attestation`

The test suite verifies the math against both.

---

## Stability + versioning

- **v0.1.x:** initial release. The 3-state result envelope is the public API; new states will be added only on a major bump. New optional fields on the result object are non-breaking.
- **No telemetry.** The library makes only the HTTP requests you ask it to (the attestation URL + the publisher-declared `pinAt`). No KXCO endpoint is contacted.
- **Reproducible builds + SLSA provenance.** Every published version of this package carries an npm provenance attestation showing the exact commit and GitHub Actions workflow that produced it. Verify with `npm view kxco-verify --json | jq .dist.attestations`.

---

## License

Apache 2.0 — see [LICENSE](./LICENSE).

This library is deliberately permissively licensed and architecturally independent of the (MIT-licensed) [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) signer. The two never share code. That separation makes the verifier auditable in isolation: a change to the signer cannot trick the verifier into trusting an unverified key.

---

## See also

- [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) — the production-tested signing library used by KnightsVault, KXCO Bank, target150, and others
- [`verify.kxco.ai`](https://verify.kxco.ai) — public web verifier (runs this library client-side)
- [`docs/verification.md`](./docs/verification.md) — full end-to-end verification flow
- [`docs/threat-model.md`](./docs/threat-model.md) — what this library does and does not protect against

## Maintainers

Shayne Heffernan · John Heffernan — [KXCO by Knightsbridge](https://kxco.ai)

Deployed in production at [target150.com](https://target150.com), [knightsbridgelaw.com](https://knightsbridgelaw.com), [livetradingnews.com](https://livetradingnews.com).
