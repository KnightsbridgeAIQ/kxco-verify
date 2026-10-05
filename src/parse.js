// Manifest parsing.
//
// Takes the raw JSON body served by an `/api/attestation`-style endpoint and
// returns a normalised, typed-ish shape that the verifier can work with —
// or a structured error if the shape is wrong.
//
// The reference manifest shape is what target150.com/api/attestation and
// chain.kxco.ai/wallet/api/.well-known/kxco-pq-attestation emit today:
//
// {
//   "manifest": {
//     "site": "example.com",
//     "alg": "ML-DSA-65",
//     "spec": "NIST FIPS 204",
//     "kid": "<16-hex-char fingerprint>",
//     "deployment": { ...site-defined fields... },
//     "msgFormat": "<template describing what was signed>"
//   },
//   "signedMessage": "<the actual bytes that were signed, as a string>",
//   "signature": { "alg": "ML-DSA-65", "encoding": "hex", "value": "<6618 hex chars>" },
//   "publicKey": { "alg": "ML-DSA-65", "encoding": "hex", "value": "<3904 hex chars>", "kid": "<same as manifest.kid>", "pinAt": "<relative URL>" }
// }
//
// We accept ML-DSA-65 and ML-DSA-87 with hex encoding. The three alg fields
// must name the same parameter set, and the public key and signature must be
// exactly that set's sizes, so the algorithm is bound to the key rather than
// taken from a label. SLH-DSA-128s and Ed25519+ML-DSA hybrid envelopes are
// reserved for later.

const HEX_RE = /^[0-9a-f]+$/i

// FIPS 204 sizes in bytes. A manifest whose key is the size of one set and
// whose alg names the other is refused here, before any verification.
const ML_DSA_SIZES = {
  'ML-DSA-65': { publicKey: 1952, signature: 3309 },
  'ML-DSA-87': { publicKey: 2592, signature: 4627 },
}
const SUPPORTED = Object.keys(ML_DSA_SIZES)
const isSupported = (alg) => typeof alg === 'string' && Object.hasOwn(ML_DSA_SIZES, alg)

/**
 * @typedef {Object} ParsedManifest
 * @property {string}  site
 * @property {string}  alg                — "ML-DSA-65" or "ML-DSA-87", matching the key and signature sizes
 * @property {string}  kid
 * @property {string}  signedMessage      — the exact bytes the signature covers
 * @property {string}  signatureHex
 * @property {string}  publicKeyHex
 * @property {string}  publicKeyKid       — kid as declared inside the publicKey block
 * @property {string=} pinAt              — relative path where the publisher recommends re-fetching the pubkey
 * @property {object=} deployment         — site-defined metadata, opaque to us
 * @property {object}  raw                — the parsed JSON in its entirety, for the UI to display
 */

/**
 * @typedef {Object} ParseError
 * @property {'parse'} kind
 * @property {string}  code        — short stable identifier (e.g. "missing_field")
 * @property {string}  message
 * @property {string=} field
 */

/**
 * Parse an attestation manifest from a JSON body. Returns either
 * { ok: true, manifest } or { ok: false, error }.
 *
 * @param {string|object} input — raw JSON string OR an already-parsed object
 * @returns {{ ok: true, manifest: ParsedManifest } | { ok: false, error: ParseError }}
 */
export function parseManifest(input) {
  let raw
  if (typeof input === 'string') {
    try { raw = JSON.parse(input) }
    catch (err) { return err_('invalid_json', `body is not valid JSON: ${err.message}`) }
    // Valid JSON is not yet a manifest. `null`, a number, a string or a
    // boolean has no fields to read, so it is refused here like any other
    // input that is not an object.
    if (!raw || typeof raw !== 'object') return err_('invalid_input', 'body must be a JSON object')
  } else if (input && typeof input === 'object') {
    raw = input
  } else {
    return err_('invalid_input', 'input must be a JSON string or an object')
  }

  const m  = raw.manifest
  const s  = raw.signature
  const pk = raw.publicKey

  if (!m  || typeof m  !== 'object') return err_('missing_field', 'top-level "manifest" is missing or not an object',  'manifest')
  if (!s  || typeof s  !== 'object') return err_('missing_field', 'top-level "signature" is missing or not an object', 'signature')
  if (!pk || typeof pk !== 'object') return err_('missing_field', 'top-level "publicKey" is missing or not an object', 'publicKey')

  // We verify ML-DSA-65 and ML-DSA-87 with hex-encoded signature + pubkey.
  // Anything else is a feature we deferred to a later version.
  const allowed = SUPPORTED.map((a) => `"${a}"`).join(' or ')
  if (!isSupported(m.alg))  return err_('unsupported_algorithm', `manifest.alg must be ${allowed} (got ${JSON.stringify(m.alg)})`,  'manifest.alg')
  if (!isSupported(s.alg))  return err_('unsupported_algorithm', `signature.alg must be ${allowed} (got ${JSON.stringify(s.alg)})`, 'signature.alg')
  if (!isSupported(pk.alg)) return err_('unsupported_algorithm', `publicKey.alg must be ${allowed} (got ${JSON.stringify(pk.alg)})`, 'publicKey.alg')
  // One parameter set per manifest: a signature or key labelled as the other
  // set is a manifest that disagrees with itself.
  if (s.alg  !== m.alg) return err_('invalid_field', `signature.alg (${JSON.stringify(s.alg)}) must match manifest.alg (${JSON.stringify(m.alg)})`, 'signature.alg')
  if (pk.alg !== m.alg) return err_('invalid_field', `publicKey.alg (${JSON.stringify(pk.alg)}) must match manifest.alg (${JSON.stringify(m.alg)})`, 'publicKey.alg')
  if (s.encoding  && s.encoding  !== 'hex') return err_('unsupported_encoding', `signature.encoding must be "hex" (got ${JSON.stringify(s.encoding)})`,  'signature.encoding')
  if (pk.encoding && pk.encoding !== 'hex') return err_('unsupported_encoding', `publicKey.encoding must be "hex" (got ${JSON.stringify(pk.encoding)})`, 'publicKey.encoding')

  if (typeof m.kid !== 'string'  || !HEX_RE.test(m.kid))  return err_('invalid_field', 'manifest.kid must be a hex string', 'manifest.kid')
  if (typeof m.site !== 'string' || !m.site.length)       return err_('invalid_field', 'manifest.site must be a non-empty string', 'manifest.site')
  if (typeof raw.signedMessage !== 'string')              return err_('missing_field', 'top-level "signedMessage" must be a string', 'signedMessage')
  if (typeof s.value  !== 'string' || !HEX_RE.test(s.value))  return err_('invalid_field', 'signature.value must be a hex string',  'signature.value')
  if (typeof pk.value !== 'string' || !HEX_RE.test(pk.value)) return err_('invalid_field', 'publicKey.value must be a hex string', 'publicKey.value')
  if (typeof pk.kid   !== 'string' || !HEX_RE.test(pk.kid))   return err_('invalid_field', 'publicKey.kid must be a hex string',   'publicKey.kid')

  // Size sanity, per parameter set. Don't trust the label saying which set it
  // is: the byte counts must be that set's, so an ML-DSA-65 key labelled
  // ML-DSA-87 (or the reverse) is refused here. Catches malformed payloads early.
  const size = ML_DSA_SIZES[m.alg]
  if (pk.value.length !== size.publicKey * 2) return err_('invalid_field', `publicKey.value must be ${size.publicKey} bytes (${size.publicKey * 2} hex chars) for ${m.alg}; got ${pk.value.length / 2}`, 'publicKey.value')
  if (s.value.length  !== size.signature * 2) return err_('invalid_field', `signature.value must be ${size.signature} bytes (${size.signature * 2} hex chars) for ${m.alg}; got ${s.value.length / 2}`,  'signature.value')

  return {
    ok: true,
    manifest: {
      site:           m.site,
      alg:            m.alg,
      kid:            m.kid.toLowerCase(),
      signedMessage:  raw.signedMessage,
      signatureHex:   s.value.toLowerCase(),
      publicKeyHex:   pk.value.toLowerCase(),
      publicKeyKid:   pk.kid.toLowerCase(),
      pinAt:          typeof pk.pinAt === 'string' ? pk.pinAt : undefined,
      deployment:     m.deployment && typeof m.deployment === 'object' ? m.deployment : undefined,
      raw,
    },
  }
}

function err_(code, message, field) {
  return { ok: false, error: { kind: 'parse', code, message, field } }
}
