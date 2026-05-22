export type VerifyState = 'valid' | 'rotated' | 'invalid' | 'error'

export interface VerifyResultError {
  kind: 'parse' | 'fetch' | 'signature' | 'consistency' | 'rotation'
  code: string
  message: string
  /** true when the error is non-fatal (math succeeded but a soft check failed). */
  soft?: boolean
  [k: string]: unknown
}

export interface VerifyResult {
  state: VerifyState
  algorithm?: 'ML-DSA-65'
  /** kid as declared inside the manifest itself */
  manifestKid?: string
  /** kid currently served at the live well-known pubkey endpoint (when fetched) */
  livePubkeyKid?: string
  /** site identifier as declared by the manifest */
  site?: string
  /** opaque deployment metadata from the manifest */
  deployment?: Record<string, unknown>
  /** full parsed manifest JSON, for UI display */
  manifestRaw?: Record<string, unknown>
  /** present when state is "error", "invalid", or "rotated" */
  error?: VerifyResultError
  attestationUrl?: string
  /** URL of the live well-known pubkey endpoint (only present when fetched) */
  pubkeyUrl?: string
  /** Date.now() at the moment verification finished */
  verifiedAtMs?: number
}

export interface VerifyUrlOpts {
  timeoutMs?: number
  maxBytes?: number
  fetchImpl?: typeof fetch
  /** When true, skip fetching the live well-known pubkey (no rotation detection). */
  skipLivePubkey?: boolean
}

/**
 * Verify an attestation manifest you already have in hand.
 * Result is "valid" / "invalid" / "error" — never "rotated" (no live fetch).
 */
export function verifyManifest(manifestBody: string | object): Promise<VerifyResult>

/**
 * Verify an attestation by URL. May return "rotated" if the live well-known
 * pubkey endpoint serves a different kid than the manifest declared.
 */
export function verifyUrl(attestationUrl: string, opts?: VerifyUrlOpts): Promise<VerifyResult>

// Re-exports.
export { parseManifest, ParseResult, ParsedManifest, ParseError } from './parse.js'
export { verifySignature, computeKid, hexToBytes, bytesToHex, hexEquals } from './verify.js'
export { getJsonBody, FetchOk, FetchErr, GetJsonBodyOpts }            from './fetch.js'
