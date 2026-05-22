// Signature math + kid math. Pure functions. No network, no I/O.
//
// We call @noble/post-quantum directly with Uint8Array so the same code runs
// in Node 18+ and in any modern browser without a polyfill. SHA-256 is taken
// from the Web Crypto API where available (browser, Node 20+), fallback to
// node:crypto's createHash where SubtleCrypto.digest is not present.

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa'

/**
 * Hex string → Uint8Array. Throws on malformed input.
 * @param {string} hex
 * @returns {Uint8Array}
 */
export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0) {
    throw new TypeError('hex input must be a string of even length')
  }
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.substr(i * 2, 2), 16)
    if (Number.isNaN(byte)) throw new TypeError(`malformed hex at offset ${i * 2}`)
    out[i] = byte
  }
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

/**
 * Verify an ML-DSA-65 signature.
 * @param {string|Uint8Array} publicKey   — 1952 bytes (3904 hex chars)
 * @param {string|Uint8Array} message     — string (utf8'd) or raw bytes
 * @param {string|Uint8Array} signature   — 3309 bytes (6618 hex chars)
 * @returns {boolean}
 */
export function verifySignature(publicKey, message, signature) {
  const pk  = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey
  const sig = typeof signature === 'string' ? hexToBytes(signature) : signature
  const msg = typeof message   === 'string' ? utf8(message)         : message
  // @noble/post-quantum signature: (publicKey, message, signature). Matches
  // the canonical wrapper in kxco-post-quantum/src/ml-dsa.js.
  try {
    return ml_dsa65.verify(pk, msg, sig)
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
