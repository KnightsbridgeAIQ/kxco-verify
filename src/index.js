// kxco-verify — public entry point.
//
// What this library is for:
//   Given a URL (or an attestation manifest you already have), determine
//   whether a site's post-quantum deploy attestation is mathematically valid.
//
// What it deliberately does NOT do:
//   - Endorse any site. A "valid" result means "the site signed its own
//     manifest with a key it published" — nothing about who the site is or
//     whether its content is trustworthy.
//   - Maintain a registry of approved (domain, kid) pairs. That is a future
//     phase of kxco-post-quantum / verify.kxco.ai and not in this library.
//   - Speak any algorithm other than ML-DSA-65 with hex encoding in this
//     release. SLH-DSA-128s and hybrid envelopes are deferred.
//
// The result envelope is intentionally three-valued so the UI can distinguish
// signature failure from in-flight key rotation:
//
//   "valid"    — signature checks against the manifest's declared kid AND
//                that kid matches the live well-known pubkey endpoint
//   "rotated"  — signature checks against the manifest's declared kid, BUT
//                the live well-known endpoint now serves a different kid
//                (interpret as: site is in the middle of a key rotation;
//                ask the user to retry shortly)
//   "invalid"  — signature does not check against the manifest-declared key
//                (interpret as: signature is forged, manifest was tampered
//                with, or the publisher's signing pipeline is broken)
//
// All other failure modes (network, malformed JSON, unsupported algorithm)
// surface as { state: "error", error: {...} }.

import { parseManifest }    from './parse.js'
import { verifySignature,
         computeKid,
         hexEquals }         from './verify.js'
import { getJsonBody }       from './fetch.js'

/**
 * @typedef {'valid'|'rotated'|'invalid'|'error'} VerifyState
 *
 * @typedef {Object} VerifyResult
 * @property {VerifyState} state
 * @property {string=}     algorithm        — e.g. "ML-DSA-65"
 * @property {string=}     manifestKid      — kid the manifest declared
 * @property {string=}     livePubkeyKid    — kid currently served at the well-known endpoint (only present when fetched)
 * @property {string=}     site             — site identifier as declared by the manifest
 * @property {object=}     deployment       — opaque deployment metadata from the manifest
 * @property {object=}     manifestRaw      — full parsed manifest JSON (for UI display)
 * @property {{ kind: string, code: string, message: string, [k: string]: any }=} error
 * @property {string=}     attestationUrl
 * @property {string=}     pubkeyUrl
 * @property {number=}     verifiedAtMs     — Date.now() at the moment verification finished
 */

/**
 * Verify an attestation manifest you already have in hand (e.g. paste from
 * the user, or already fetched). Does NOT contact the live well-known
 * endpoint — so the result is at best "valid" or "invalid" but never "rotated".
 *
 * @param {string|object} manifestBody — raw JSON body or parsed object
 * @returns {Promise<VerifyResult>}
 */
export async function verifyManifest(manifestBody) {
  const parsed = parseManifest(manifestBody)
  if (!parsed.ok) return { state: 'error', error: parsed.error, verifiedAtMs: Date.now() }
  const m = parsed.manifest

  // The publisher's own consistency check: the kid embedded inside the
  // publicKey block must match what manifest.kid says, AND must match the
  // SHA-256 fingerprint of the pubkey bytes. If either disagrees, the
  // manifest is internally inconsistent — treat as invalid before we even
  // run the slow signature math.
  const recomputedKid = await computeKid(m.publicKeyHex)
  if (!hexEquals(recomputedKid, m.kid) || !hexEquals(recomputedKid, m.publicKeyKid)) {
    return {
      state:       'invalid',
      algorithm:   m.alg,
      manifestKid: m.kid,
      site:        m.site,
      manifestRaw: m.raw,
      error: {
        kind: 'consistency',
        code: 'kid_mismatch_internal',
        message: `manifest.kid (${m.kid}) and/or publicKey.kid (${m.publicKeyKid}) disagree with SHA-256(publicKey) (${recomputedKid})`,
      },
      verifiedAtMs: Date.now(),
    }
  }

  const sigValid = verifySignature(m.publicKeyHex, m.signedMessage, m.signatureHex)
  return {
    state:       sigValid ? 'valid' : 'invalid',
    algorithm:   m.alg,
    manifestKid: m.kid,
    site:        m.site,
    deployment:  m.deployment,
    manifestRaw: m.raw,
    error: sigValid ? undefined : {
      kind: 'signature',
      code: 'invalid_signature',
      message: 'signature does not verify under the manifest-declared public key',
    },
    verifiedAtMs: Date.now(),
  }
}

/**
 * Verify an attestation by URL.
 *
 *   1. Fetch the attestation URL.
 *   2. Parse + math-verify it (as verifyManifest does).
 *   3. If the manifest declared `publicKey.pinAt`, also fetch that endpoint
 *      and compare its kid to the manifest's. A mismatch downgrades a "valid"
 *      result to "rotated" — the signature checks against the kid the
 *      manifest declared, but the live endpoint now serves a different kid.
 *
 * @param {string} attestationUrl
 * @param {{ timeoutMs?: number, maxBytes?: number, fetchImpl?: typeof fetch, skipLivePubkey?: boolean }} [opts]
 * @returns {Promise<VerifyResult>}
 */
export async function verifyUrl(attestationUrl, opts = {}) {
  const t0 = Date.now()
  const fetched = await getJsonBody(attestationUrl, opts)
  if (!fetched.ok) {
    return { state: 'error', error: fetched.error, attestationUrl, verifiedAtMs: Date.now() }
  }

  const result = await verifyManifest(fetched.body)
  result.attestationUrl = attestationUrl

  // Math failed already; no benefit in fetching the live pubkey.
  if (result.state !== 'valid' || opts.skipLivePubkey) {
    result.verifiedAtMs = Date.now()
    return result
  }

  // Resolve pinAt against the attestation URL's origin.
  const pinAt = result.manifestRaw?.publicKey?.pinAt
  if (typeof pinAt !== 'string' || !pinAt) {
    // No pinAt → publisher didn't tell us where the live pubkey is, so we
    // cannot detect rotation. Return valid as-is and let the UI explain.
    result.verifiedAtMs = Date.now()
    return result
  }

  let pubkeyUrl
  try {
    pubkeyUrl = new URL(pinAt, attestationUrl).toString()
  } catch (err) {
    result.error = { kind: 'consistency', code: 'invalid_pinAt', message: `manifest.publicKey.pinAt is not a resolvable URL: ${err.message}` }
    result.state = 'invalid'
    result.verifiedAtMs = Date.now()
    return result
  }

  const livePk = await getJsonBody(pubkeyUrl, opts)
  if (!livePk.ok) {
    // Couldn't fetch the live pubkey. Don't downgrade — the math succeeded.
    // Tell the UI we couldn't confirm rotation status.
    result.pubkeyUrl = pubkeyUrl
    result.error = { kind: 'fetch', code: livePk.error.code, message: `could not fetch live pubkey at ${pubkeyUrl}: ${livePk.error.message}`, soft: true }
    result.verifiedAtMs = Date.now()
    return result
  }

  let liveJson
  try { liveJson = JSON.parse(livePk.body) }
  catch (err) {
    result.pubkeyUrl = pubkeyUrl
    result.error = { kind: 'parse', code: 'invalid_live_pubkey_json', message: `live pubkey body is not JSON: ${err.message}`, soft: true }
    result.verifiedAtMs = Date.now()
    return result
  }

  // Two ways the publisher may serve the kid: explicit "kid" field, or we
  // recompute from the publicKey hex. Prefer recompute as the source of truth.
  const livePubkeyHex = typeof liveJson.publicKey === 'string'
    ? liveJson.publicKey
    : (typeof liveJson?.value === 'string' ? liveJson.value : null)
  if (!livePubkeyHex) {
    result.pubkeyUrl = pubkeyUrl
    result.error = { kind: 'consistency', code: 'live_pubkey_missing', message: 'live well-known endpoint did not return a publicKey field', soft: true }
    result.verifiedAtMs = Date.now()
    return result
  }
  const liveKid = await computeKid(livePubkeyHex)
  result.pubkeyUrl     = pubkeyUrl
  result.livePubkeyKid = liveKid

  if (!hexEquals(liveKid, result.manifestKid)) {
    // Signature checked against manifest.kid but the well-known now serves
    // a different kid. This is the rotation signal.
    result.state = 'rotated'
    result.error = {
      kind: 'rotation',
      code: 'live_kid_mismatch',
      message: `signature is valid for kid ${result.manifestKid}, but the live well-known endpoint now serves kid ${liveKid}. The site is likely mid key-rotation; retry shortly.`,
    }
  }

  result.verifiedAtMs = Date.now()
  return result
}

// Re-export the lower-level helpers for users who want to compose.
export { parseManifest }      from './parse.js'
export { verifySignature,
         computeKid,
         hexToBytes,
         bytesToHex,
         hexEquals }          from './verify.js'
export { getJsonBody }        from './fetch.js'
