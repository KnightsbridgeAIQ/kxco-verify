# Threat model

> **Plain-English summary first.** A `"valid"` result from this library means one specific thing: the signature is mathematically valid under the public key the site itself published, and that key matches the site's live well-known endpoint. **It does not mean KXCO has vetted the site.** Anyone with a GitHub account and 30 seconds can run `kxco-post-quantum`, generate a keypair, and publish a self-signed attestation that this library will mark `"valid"`. That is intentional for v0.1.x — verification is a cryptographic claim about the signer's possession of a key, not a trust claim about who the signer is.

This document explains exactly what the library does and does not protect against. Read it before you use `state: "valid"` to make any trust decision in your UI.

## What "valid" proves

A `"valid"` result establishes all of these:

| Property                                                                                            | How it's proven                                              |
|-----------------------------------------------------------------------------------------------------|--------------------------------------------------------------|
| The signature is over the exact `signedMessage` field that was in the manifest body you fetched     | ML-DSA-65 verify                                             |
| The signature was produced by the private key whose public counterpart is in the same manifest body | ML-DSA-65 verify                                             |
| The kid in the manifest is the actual SHA-256 fingerprint of the embedded public key                | Recomputed before signature verification                     |
| The same public key is currently being served at the publisher's `pinAt` well-known endpoint        | Second fetch, kid recompute                                  |
| The manifest body has not been altered in flight between fetch and verification in your process     | Implied by the signature math                                |

## What "valid" does NOT prove

In order of how often this confuses people:

| Claim                                                                              | Why the library can't prove it                                                                                                                                                          |
|------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **The site is operated by who it claims to be.**                                   | There is no KXCO-controlled registry of approved `(domain, kid)` pairs in v0.1.x. Any operator can generate any keypair and publish any manifest.                                       |
| **The site's content is trustworthy or safe.**                                     | The signature only covers the deployment-stable signed message — not the rest of the page, not the site's behaviour, not its TLS certificate, not its operator.                         |
| **KXCO has audited or endorses this site.**                                        | KXCO performs no human review. The verifier runs deterministic math; KXCO does not see most verifications because the library runs client-side.                                         |
| **The manifest was signed at the timestamp the publisher claims.**                 | There is no transparency log in v0.1.x. The publisher can sign at any time and assert any signed message. (Future phases will add a Rekor-style log.)                                   |
| **The public key has not been used to sign other things.**                         | The library has no log of past attestations. A leaked private key can be used to sign anything until the publisher rotates and the well-known endpoint serves the new kid.              |
| **The site has not been compromised since the manifest was signed.**               | A compromised publisher will produce manifests that look exactly as valid as legitimate ones until the operator rotates the key.                                                        |
| **The manifest's `deployment.git_commit` field actually corresponds to deployed code.** | The signer chose those fields freely; only the publisher's signing pipeline ties them to anything real. The library treats them as opaque metadata for display.                      |

## Attack scenarios the library does NOT defend against

### 1. Self-signed badge laundering

**Setup:** Attacker registers `kxc0-bank.ai` (zero instead of o), runs `npm install kxco-post-quantum`, generates a keypair in 30 seconds, publishes a manifest and well-known endpoint. Submits the URL to `verify.kxco.ai`. Gets a green `VALID` card. Screenshot circulates as proof of KXCO endorsement.

**Why it works:** The cryptography is real — the attacker really does possess the key. The library has no concept of "approved publisher", because there is no KXCO-controlled registry in v0.1.x.

**Mitigation in v0.1.x:** None. The `verify.kxco.ai` UI states explicitly that a valid result means only "the site possesses the private key it claims to publish — nothing more". Consumers of this library should display equivalent copy. See [`README.md`](../README.md) for the canonical wording.

**Planned mitigation:** Phase 2 introduces a KXCO-controlled domain/key registry. The verifier will then surface a separate "registered publisher" status alongside the math result. Until then, treat `"valid"` as a tamper-evidence signal only.

### 2. Stale-cache rotation false-negative

**Setup:** Publisher rotates their signing key. CDN cache on the attestation manifest has 24 hours of TTL left. For up to 24 hours, every verification of that publisher's URL returns `"rotated"` — signature valid against an old kid, live endpoint serves a new one.

**Why it works:** This is correct behaviour, but the UX cost is real. A user can't distinguish "rotation in progress" from "key was compromised and the publisher pulled the bad key" without inspecting the deployment metadata.

**Mitigation in v0.1.x:** The library returns `state: "rotated"` (not `"invalid"`) with code `live_kid_mismatch` so the UI can present this as "retry shortly" rather than "compromise". Publishers should also document a rotation procedure (publish new manifest with new kid BEFORE rotating the well-known endpoint; allow at least one CDN TTL between the two).

### 3. Hostile attestation host

**Setup:** Attacker controls the network path between the verifier and the attestation endpoint (e.g. a malicious WiFi captive portal). They intercept the fetch and return a manifest of their own.

**Why it works:** Without TLS pinning, the verifier trusts whatever the network delivers.

**Mitigation in v0.1.x:** The library fetches over whatever transport the URL specifies (HTTPS is recommended). For HTTPS, you inherit the browser's CA-trust model. The library does NOT add additional TLS verification beyond what the platform fetch already does.

If your threat model includes hostile MitM on the attestation fetch path: distribute the publisher's pinned `kid` out of band (e.g. via DNS DNSSEC TXT record, software supply-chain channel) and compare it to the manifest's `kid` field. The library makes this comparison easy: `verifyManifest(...)` returns `manifestKid` in the result.

### 4. Compromised publisher private key

**Setup:** The publisher's `KXCO_KEY_MASTER` env var leaks (logged, screenshotted, exfiltrated from an EC2 metadata endpoint, exposed in a debugger). Attacker can now produce manifests that the library marks `"valid"` indefinitely.

**Why it works:** The library has no way to know the key has leaked.

**Mitigation in v0.1.x:** Publisher must rotate the master, which changes the derived kid. The library will then mark old-key attestations as `"rotated"` once the well-known endpoint serves the new kid. **However**, an attacker who captured the old manifest can keep showing it; the library cannot tell that a manifest is stale by date.

**Planned mitigation:** A transparency log of every (kid, signed_at) seen in the wild — the same primitive Sigstore uses for binary signing. Phase 2 of the brief.

### 5. Verifier-as-attacker (when running this library server-side)

**Setup:** A site embeds this library on the server side and returns `verifiedAtMs` + `state` to clients. The server lies and returns `"valid"` for any URL.

**Why it works:** Trust is centralised in the server running the verifier.

**Mitigation in v0.1.x:** This library is small enough (~600 lines) that an end user can run it themselves with `npx kxco-verify-smoke <url>` and reach the same conclusion. The public web verifier at `verify.kxco.ai` is deliberately built client-side so no KXCO server is in the trust path; the browser fetches the manifest directly and runs the math in-tab. If your application needs to consume `kxco-verify` results from another service, treat that service as the trust root, not the math.

## Implementation-level threats (handled in the library)

The library does defend against these:

| Threat                                                                       | Defense                                                                                                                                                  |
|------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| Memory exhaustion via huge attestation body                                  | `maxBytes` cap (default 200 KB) on every fetch, enforced via a streaming reader that cancels the underlying stream when the cap is hit                   |
| Slow / unresponsive attestation host                                         | `timeoutMs` (default 3000 ms) on every fetch, implemented via `AbortController`                                                                          |
| Malformed JSON                                                               | Wrapped in try/catch; returns `state: "error"` with code `invalid_json`                                                                                  |
| Wrong-size public key or signature (truncation / padding attacks)            | Byte-count check before any crypto runs; rejects with code `invalid_field`                                                                               |
| Algorithm-confusion (server claims ML-DSA-65 but ships an Ed25519 sig)       | Strict algorithm allow-list (`ML-DSA-65` only in v0.1.x)                                                                                                 |
| Internally inconsistent manifest (`manifest.kid` ≠ SHA-256(`publicKey`))     | Recomputed kid is checked before signature verification; returns `state: "invalid"` with code `kid_mismatch_internal`                                    |
| Untrusted `pinAt` (e.g., `pinAt: "javascript:..."` or `file://`)             | Resolved via `new URL(pinAt, attestationUrl)`; only http/https URLs are accepted by the fetch helper, others rejected with `invalid_url`                 |
| Verifier crash on hostile input                                              | All public functions return tagged results — no exceptions thrown to the caller in normal use                                                            |
| Browser SSRF                                                                 | None — the library never makes requests to URLs the caller didn't explicitly pass. CORS at the target prevents data exfiltration in cross-origin cases   |
| Server-side SSRF (when used in Node)                                         | URL must be absolute http/https. Library does NOT block internal-network IPs — that's the caller's responsibility. Run it in a sandboxed environment if you accept untrusted URLs server-side. |

## What's coming in later phases

Per the [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) evolution brief:

- **Phase 2:** key registry + revocation. Adds a `"unregistered"` and `"revoked"` state on top of math verification.
- **Phase 2/3:** transparency log. Adds `anchorTxId` to the result for attestations that have been anchored. The verifier will be able to detect manifests that were signed but never published.
- **Phase 4:** third-party audit. Until then, treat the math here as trusted only to the extent you trust `@noble/post-quantum` (which has had multiple external reviews) and this library's small surface (which has not).

## Reporting a security issue

See [`SECURITY.md`](../SECURITY.md) in the repo root if/when published. In the interim, email `hello@kxco.ai` with subject `[kxco-verify] SECURITY`.
