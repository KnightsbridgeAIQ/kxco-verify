/** Hex string → Uint8Array. Throws on malformed input. */
export function hexToBytes(hex: string): Uint8Array

/** Uint8Array → hex string (lowercase). */
export function bytesToHex(bytes: Uint8Array): string

/** UTF-8 string → Uint8Array. */
export function utf8(s: string): Uint8Array

/**
 * Compute the kxco kid (key identifier) of a public key —
 * first 16 hex chars of SHA-256(rawBytes).
 */
export function computeKid(publicKey: Uint8Array | string): Promise<string>

/**
 * Verify an ML-DSA-65 or ML-DSA-87 signature.
 *
 * The public key decides the parameter set: 1952 bytes is ML-DSA-65, 2592 is
 * ML-DSA-87. Pass `alg` to require a set; a key or signature that is not that
 * set's size returns false. An unsupported `alg` throws a TypeError.
 */
export function verifySignature(
  publicKey: Uint8Array | string,
  message:   Uint8Array | string,
  signature: Uint8Array | string,
  alg?:      'ML-DSA-65' | 'ML-DSA-87',
): boolean

/** Length-equal hex comparison. */
export function hexEquals(a: string, b: string): boolean
