# Verification flow — end to end

> **Read alongside [`threat-model.md`](./threat-model.md).** This document explains *what* happens. The threat model explains what the result does and does not prove.

This document walks through exactly what `kxco-verify` does when you call `verifyUrl(attestationUrl)`. Every step is observable: you can re-run any of them by hand with `curl` and `openssl` and reach the same conclusion.

## The attestation manifest (what a signer publishes)

Any site using [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) publishes two JSON endpoints:

| Endpoint                       | Purpose                                                    |
|--------------------------------|------------------------------------------------------------|
| `/api/attestation` (or similar) | The signed attestation manifest itself                     |
| `/.well-known/<id>-pq-pubkey`   | The live ML-DSA-65 public key for the site                 |

The attestation body has this shape:

```jsonc
{
  "manifest": {
    "site":      "example.com",
    "alg":       "ML-DSA-65",
    "spec":      "NIST FIPS 204",
    "kid":       "<16 hex chars — SHA-256(publicKey)[:8]>",
    "deployment": {
      // opaque, site-defined: git commit, env, region, etc.
    },
    "msgFormat": "<template describing what was signed, for human readers>"
  },
  "signedMessage": "<the actual bytes the signature covers, as a string>",
  "signature": {
    "alg": "ML-DSA-65", "encoding": "hex",
    "value": "<6618 hex chars — 3309 bytes>"
  },
  "publicKey": {
    "alg": "ML-DSA-65", "encoding": "hex",
    "value": "<3904 hex chars — 1952 bytes>",
    "kid":   "<same as manifest.kid>",
    "pinAt": "<URL where the live well-known pubkey lives>"
  }
}
```

The well-known endpoint serves the current production public key:

```jsonc
{
  "alg":         "ML-DSA-65",
  "spec":        "NIST FIPS 204",
  "publicKey":   "<3904 hex chars>",
  "kid":         "<16 hex chars>",
  "sigEncoding": "hex"
}
```

## Step-by-step verification

When you call `verifyUrl('https://example.com/api/attestation')`, the library performs the following six steps. The last one is the only one that requires a second network round trip.

### 1. Fetch the attestation manifest

`GET <attestationUrl>` with a hard timeout (default 3000 ms) and a maximum response size (default 200 KB). If the fetch fails, returns `state: "error"`.

```bash
curl -fsS https://www.target150.com/api/attestation | jq
```

### 2. Parse + validate the shape

Reject:
- Non-JSON bodies
- Missing `manifest`, `signature`, or `publicKey` top-level fields
- Algorithm fields that aren't `"ML-DSA-65"`
- Encoding fields that aren't `"hex"`
- Public-key hex that isn't exactly 3904 chars (1952 bytes, the ML-DSA-65 pubkey size)
- Signature hex that isn't exactly 6618 chars (3309 bytes, the ML-DSA-65 sig size)
- Non-hex `kid` fields

Byte-count sanity catches malformed payloads before any expensive crypto runs.

### 3. Recompute the kid from the public key

```
recomputedKid = SHA-256(publicKey.value as bytes)[:8 bytes].hex()
```

This must match BOTH `manifest.kid` AND `publicKey.kid`. If either disagrees, the manifest is internally inconsistent — returns `state: "invalid"` with code `kid_mismatch_internal`. Done before the signature check, because if the publisher couldn't even produce a consistent kid for their own key, the signature can't possibly verify.

Verify by hand:

```bash
curl -fsS https://www.target150.com/api/attestation | jq -r .publicKey.value \
  | xxd -r -p | openssl dgst -sha256 -binary | xxd -p | cut -c1-16
# → 680f9af0bb44de3f
```

### 4. Verify the ML-DSA-65 signature

```js
ml_dsa65.verify(publicKey, signedMessage, signature)
```

The signature must mathematically verify under the manifest-declared public key. This is the cryptographic core. If it fails, returns `state: "invalid"` with code `invalid_signature`. If it succeeds, we move to the rotation check.

The primitive is `@noble/post-quantum`'s audited TypeScript implementation of ML-DSA-65 (Dilithium3, NIST FIPS 204). For more on what this primitive does and does not prove, see [`threat-model.md`](./threat-model.md).

### 5. Resolve the live pubkey URL

If `manifest.publicKey.pinAt` is present, resolve it against the attestation URL using standard URL composition (`new URL(pinAt, attestationUrl)`). A relative path like `kxco-pq-pubkey` resolves to the same directory as the attestation; an absolute path like `/.well-known/foo` resolves to the site root.

If `pinAt` is missing, skip step 6 and return `state: "valid"` directly. The result will lack a `livePubkeyKid` field — the publisher chose not to expose rotation detection.

### 6. Cross-check against the live pubkey

`GET <pubkeyUrl>` with the same timeout / size cap. Recompute the kid from the live pubkey's bytes the same way as step 3. Then:

| Condition                                  | Result                                              |
|--------------------------------------------|-----------------------------------------------------|
| `liveKid === manifest.kid`                 | `state: "valid"`                                    |
| `liveKid !== manifest.kid`                 | `state: "rotated"` with code `live_kid_mismatch`    |
| Live fetch fails (network, 5xx, malformed) | `state: "valid"` with a **soft** error on the result; we don't downgrade a valid signature just because the publisher's well-known endpoint is temporarily down |

`"rotated"` is the signal that the publisher rotated their key between when the attestation was published and now. The signature is mathematically fine — it just covers a kid that's no longer the current production key.

## Reproducing the verifier by hand

If you don't trust the library, reproduce the result with `curl`, `jq`, `xxd`, and a one-liner that calls `@noble/post-quantum`:

```bash
# 1. fetch attestation
curl -fsS https://www.target150.com/api/attestation > att.json

# 2. recompute kid from the embedded public key
jq -r .publicKey.value att.json | xxd -r -p \
  | openssl dgst -sha256 -binary | xxd -p | cut -c1-16
# expected: same as $(jq -r .manifest.kid att.json)

# 3. extract the signed message, public key, and signature
MSG=$(jq -r .signedMessage      att.json)
PK_HEX=$(jq -r .publicKey.value att.json)
SIG_HEX=$(jq -r .signature.value att.json)

# 4. verify (Node ≥18, ESM)
node -e "
  import('@noble/post-quantum/ml-dsa').then(({ml_dsa65}) => {
    const hex = h => Uint8Array.from(h.match(/../g).map(b=>parseInt(b,16)))
    const ok  = ml_dsa65.verify(hex('$PK_HEX'), new TextEncoder().encode('$MSG'), hex('$SIG_HEX'))
    console.log(ok ? 'valid' : 'invalid')
  })
"
```

If that prints `valid`, the math is the same the library reports. No KXCO-controlled code runs.

## Trust model — short form

A `"valid"` result proves the publisher possesses the private key whose public counterpart they published. **It does not prove anything about who the publisher is**, whether they are who they claim to be, or whether their site is trustworthy. See [`threat-model.md`](./threat-model.md) for the long form, including the "badge laundering" scenario this library deliberately does not defend against.
