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
// We accept only ML-DSA-65 with hex encoding in this version. SLH-DSA-128s
// and Ed25519+ML-DSA hybrid envelopes are reserved for later.

const HEX_RE = /^[0-9a-f]+$/i

/**
 * @typedef {Object} ParsedManifest
 * @property {string}  site
 * @property {string}  alg                — must be "ML-DSA-65" in this version
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

  // We only verify ML-DSA-65 with hex-encoded signature + pubkey in this
  // release. Anything else is a feature we deferred to a later version.
  if (m.alg  !== 'ML-DSA-65') return err_('unsupported_algorithm', `manifest.alg must be "ML-DSA-65" (got ${JSON.stringify(m.alg)})`,  'manifest.alg')
  if (s.alg  !== 'ML-DSA-65') return err_('unsupported_algorithm', `signature.alg must be "ML-DSA-65" (got ${JSON.stringify(s.alg)})`, 'signature.alg')
  if (pk.alg !== 'ML-DSA-65') return err_('unsupported_algorithm', `publicKey.alg must be "ML-DSA-65" (got ${JSON.stringify(pk.alg)})`, 'publicKey.alg')
  if (s.encoding  && s.encoding  !== 'hex') return err_('unsupported_encoding', `signature.encoding must be "hex" (got ${JSON.stringify(s.encoding)})`,  'signature.encoding')
  if (pk.encoding && pk.encoding !== 'hex') return err_('unsupported_encoding', `publicKey.encoding must be "hex" (got ${JSON.stringify(pk.encoding)})`, 'publicKey.encoding')

  if (typeof m.kid !== 'string'  || !HEX_RE.test(m.kid))  return err_('invalid_field', 'manifest.kid must be a hex string', 'manifest.kid')
  if (typeof m.site !== 'string' || !m.site.length)       return err_('invalid_field', 'manifest.site must be a non-empty string', 'manifest.site')
  if (typeof raw.signedMessage !== 'string')              return err_('missing_field', 'top-level "signedMessage" must be a string', 'signedMessage')
  if (typeof s.value  !== 'string' || !HEX_RE.test(s.value))  return err_('invalid_field', 'signature.value must be a hex string',  'signature.value')
  if (typeof pk.value !== 'string' || !HEX_RE.test(pk.value)) return err_('invalid_field', 'publicKey.value must be a hex string', 'publicKey.value')
  if (typeof pk.kid   !== 'string' || !HEX_RE.test(pk.kid))   return err_('invalid_field', 'publicKey.kid must be a hex string',   'publicKey.kid')

  // ML-DSA-65 size sanity. Don't trust the message saying "ML-DSA-65" —
  // verify the byte counts match the spec. Catches malformed payloads early.
  if (pk.value.length !== 3904) return err_('invalid_field', `publicKey.value must be 1952 bytes (3904 hex chars); got ${pk.value.length / 2}`, 'publicKey.value')
  if (s.value.length  !== 6618) return err_('invalid_field', `signature.value must be 3309 bytes (6618 hex chars); got ${s.value.length / 2}`,  'signature.value')

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
