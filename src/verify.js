// Signature math + kid math. Pure functions. No network, no I/O.
//
// We call @noble/post-quantum directly with Uint8Array so the same code runs
// in Node 18+ and in any modern browser without a polyfill. SHA-256 is taken
// from the Web Crypto API where available (browser, Node 20+), fallback to
// node:crypto's createHash where SubtleCrypto.digest is not present.

import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'

// The parameter sets this verifier speaks, with their FIPS 204 public-key sizes.
// The key decides which one a signature is checked under: its length picks
// the set, and a key that is not exactly a set's size verifies nothing.
const ML_DSA = {
  'ML-DSA-65': { primitive: ml_dsa65, publicKey: 1952 },
  'ML-DSA-87': { primitive: ml_dsa87, publicKey: 2592 },
}

/**
 * Hex string → Uint8Array. Throws on malformed input.
 * @param {string} hex
 * @returns {Uint8Array}
 */
export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0) {
    throw new TypeError('hex input must be a string of even length')
  }
  // Checked up front because parseInt reads a prefix: on its own it would take
  // '0g' as 0, '+a' as 10 and '-1' as 255, giving one byte several spellings.
  const bad = hex.search(/[^0-9a-fA-F]/)
  if (bad !== -1) throw new TypeError(`malformed hex at offset ${bad}`)
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16)
  return out
}

/**
 * Uint8Array → hex string (lowercase).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToHex(bytes) {
  let out = ''
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0')
  return out
}

/**
 * UTF-8 string → Uint8Array.
 * @param {string} s
 * @returns {Uint8Array}
 */
export function utf8(s) {
  return new TextEncoder().encode(s)
}

/**
 * Compute the kxco kid (key identifier) of a public key — first 16 hex chars
 * of SHA-256(rawBytes). Matches the algorithm in kxco-post-quantum's
 * `fingerprint()`. Async because SubtleCrypto.digest is async.
 *
 * @param {Uint8Array|string} publicKey — raw bytes or hex string
 * @returns {Promise<string>} 16-char lowercase hex
 */
export async function computeKid(publicKey) {
  const bytes = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey
  const subtle = globalThis.crypto && globalThis.crypto.subtle
  let hashBytes
  if (subtle && typeof subtle.digest === 'function') {
    const ab = await subtle.digest('SHA-256', bytes)
    hashBytes = new Uint8Array(ab)
  } else {
    // Node fallback. Only reached on Node <20 without globalThis.crypto.
    const { createHash } = await import('node:crypto')
    hashBytes = createHash('sha256').update(bytes).digest()
  }
  return bytesToHex(hashBytes.subarray(0, 8))
}

// The ML-DSA parameter set a public key's bytes belong to, by length, or null.
const algorithmOfKey = (pk) => Object.keys(ML_DSA).find((alg) => ML_DSA[alg].publicKey === pk?.length) ?? null

/**
 * Verify an ML-DSA-65 or ML-DSA-87 signature.
 *
 * The public key decides the parameter set: 1952 bytes is ML-DSA-65 and 2592
 * is ML-DSA-87. Pass `alg` to require a set; a key or signature that is not
 * that set's size then returns false, so a key of one set is never checked
 * as the other. An `alg` this verifier does not speak throws, as malformed
 * hex does, because it is a caller error rather than a failed signature.
 *
 * @param {string|Uint8Array} publicKey   — 1952 or 2592 bytes (3904 or 5184 hex chars)
 * @param {string|Uint8Array} message     — string (utf8'd) or raw bytes
 * @param {string|Uint8Array} signature   — 3309 or 4627 bytes (6618 or 9254 hex chars)
 * @param {'ML-DSA-65'|'ML-DSA-87'} [alg] — the set the caller requires
 * @returns {boolean}
 */
export function verifySignature(publicKey, message, signature, alg) {
  if (alg !== undefined && !(typeof alg === 'string' && Object.hasOwn(ML_DSA, alg))) {
    throw new TypeError(`unsupported algorithm ${JSON.stringify(alg)}: expected "ML-DSA-65" or "ML-DSA-87"`)
  }
  const pk  = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey
  const sig = typeof signature === 'string' ? hexToBytes(signature) : signature
  const msg = typeof message   === 'string' ? utf8(message)         : message
  const set = ML_DSA[alg ?? algorithmOfKey(pk)]
  if (!set) return false
  // Checked here, not left to the primitive: a named set must match the key.
  if (pk?.length !== set.publicKey) return false
  // @noble/post-quantum ≥0.6 signature order: (signature, message, publicKey).
  // Matches the canonical wrapper in kxco-post-quantum/src/ml-dsa.js. The
  // primitive refuses a key or signature that is not its set's length, so a
  // key of one set is never checked as the other.
  try {
    return set.primitive.verify(sig, msg, pk)
  } catch {
    return false
  }
}

/**
 * Constant-time-ish hex comparison. Both inputs are hex strings.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function hexEquals(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}
