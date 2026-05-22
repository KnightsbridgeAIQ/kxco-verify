# Security policy

## Supported versions

Only the latest minor on the latest major is supported with security fixes during this v0.x period. Once we reach v1.0, the policy moves to "latest major + previous major".

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |
| < 0.1   | ❌        |

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.**

Email `hello@kxco.ai` with subject line: `[kxco-verify] SECURITY: <one-line summary>`

If you need PGP, also fetch the platform's ML-DSA-65 public key from
`https://chain.kxco.ai/wallet/api/.well-known/kxco-pq-pubkey` and sign your
report with your own key — we'll respond in kind.

Acknowledgement within **2 business days**. Triage decision within **5 business days**.

## What we treat as in-scope

- Bugs in the cryptographic logic that could cause a signature to be accepted when it should not be (false negative on a tampered manifest, kid mismatch missed, algorithm confusion).
- Resource exhaustion / DoS in the verifier (memory blow-up via oversized response, hung fetch despite timeout, infinite loop via crafted input).
- Cross-origin or SSRF issues introduced by the library beyond the obvious "this is a URL fetcher".
- Documentation that misleads consumers into believing a `"valid"` result means more than the threat model says it means.

## What we treat as out-of-scope

- Anything tracked in [`docs/threat-model.md`](./docs/threat-model.md) under "What 'valid' does NOT prove" or "Attack scenarios the library does NOT defend against". These are deliberate limitations of v0.1.x, called out explicitly. Phase 2 of the brief addresses several of them (registry, transparency log).
- Vulnerabilities in `@noble/post-quantum` itself — report those at [noble-post-quantum/security](https://github.com/paulmillr/noble-post-quantum/security).
- Vulnerabilities in `verify.kxco.ai`'s deployment infrastructure (nginx, Let's Encrypt, DigitalOcean) — those are the operator's responsibility; the library is portable to any host.

## Bug bounty

No formal bounty programme yet. We commit to public acknowledgement on every confirmed fix, and to crediting reporters in the changelog unless they request anonymity. Cash bounties may be offered for critical findings at our discretion during this v0.x period.
