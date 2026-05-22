export interface ParsedManifest {
  site: string
  alg: 'ML-DSA-65'
  kid: string
  signedMessage: string
  signatureHex: string
  publicKeyHex: string
  publicKeyKid: string
  pinAt?: string
  deployment?: Record<string, unknown>
  raw: Record<string, unknown>
}

export interface ParseError {
  kind: 'parse'
  code:
    | 'invalid_json'
    | 'invalid_input'
    | 'missing_field'
    | 'invalid_field'
    | 'unsupported_algorithm'
    | 'unsupported_encoding'
  message: string
  field?: string
}

export type ParseResult =
  | { ok: true;  manifest: ParsedManifest }
  | { ok: false; error: ParseError }

export function parseManifest(input: string | object): ParseResult
