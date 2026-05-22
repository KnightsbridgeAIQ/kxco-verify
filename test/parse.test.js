// Tests for parseManifest — input validation, supported algorithms, byte-count sanity.

import { test }     from 'node:test'
import assert       from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

import { parseManifest } from '../src/parse.js'

const FIXTURES = [
  'fixtures/wallet-attestation.json',
  'fixtures/target150-attestation.json',
]

for (const path of FIXTURES) {
  test(`parseManifest accepts the live fixture ${path}`, async () => {
    const body = await readFile(new URL(`../${path}`, import.meta.url), 'utf-8')
    const r = parseManifest(body)
    assert.equal(r.ok, true, JSON.stringify(r.error))
    assert.equal(r.manifest.alg, 'ML-DSA-65')
    assert.equal(r.manifest.kid.length, 16)
    assert.equal(r.manifest.publicKeyHex.length, 3904)
    assert.equal(r.manifest.signatureHex.length, 6618)
    assert.equal(r.manifest.kid, r.manifest.publicKeyKid)
    assert.ok(typeof r.manifest.signedMessage === 'string' && r.manifest.signedMessage.length > 0)
  })
}

test('parseManifest accepts a pre-parsed object as well as a JSON string', async () => {
  const body = await readFile(new URL('../fixtures/wallet-attestation.json', import.meta.url), 'utf-8')
  const obj  = JSON.parse(body)
  const r1   = parseManifest(body)
  const r2   = parseManifest(obj)
  assert.equal(r1.ok, true)
  assert.equal(r2.ok, true)
  assert.equal(r1.manifest.kid, r2.manifest.kid)
})

test('parseManifest rejects invalid JSON', () => {
  const r = parseManifest('{not json')
  assert.equal(r.ok, false)
  assert.equal(r.error.code, 'invalid_json')
})

test('parseManifest rejects non-string non-object input', () => {
  const r = parseManifest(42)
  assert.equal(r.ok, false)
  assert.equal(r.error.code, 'invalid_input')
})

test('parseManifest rejects missing manifest block', () => {
  const r = parseManifest({ signature: {}, publicKey: {} })
  assert.equal(r.ok, false)
  assert.equal(r.error.code, 'missing_field')
  assert.equal(r.error.field, 'manifest')
})

test('parseManifest rejects unsupported algorithm', () => {
  const r = parseManifest({
    manifest:      { site: 's', alg: 'Ed25519', kid: 'aa'.repeat(8) },
    signedMessage: 'm',
    signature:     { alg: 'Ed25519', encoding: 'hex', value: 'aa'.repeat(64) },
    publicKey:     { alg: 'Ed25519', encoding: 'hex', value: 'aa'.repeat(32), kid: 'aa'.repeat(8) },
  })
  assert.equal(r.ok, false)
  assert.equal(r.error.code, 'unsupported_algorithm')
})

test('parseManifest rejects wrong public-key byte count', async () => {
  const body = await readFile(new URL('../fixtures/wallet-attestation.json', import.meta.url), 'utf-8')
  const obj  = JSON.parse(body)
  obj.publicKey.value = obj.publicKey.value.slice(0, 100)  // truncated
  const r = parseManifest(obj)
  assert.equal(r.ok, false)
  assert.equal(r.error.code, 'invalid_field')
  assert.equal(r.error.field, 'publicKey.value')
})

test('parseManifest rejects wrong signature byte count', async () => {
  const body = await readFile(new URL('../fixtures/wallet-attestation.json', import.meta.url), 'utf-8')
  const obj  = JSON.parse(body)
  obj.signature.value = obj.signature.value.slice(0, 200)
  const r = parseManifest(obj)
  assert.equal(r.ok, false)
  assert.equal(r.error.code, 'invalid_field')
  assert.equal(r.error.field, 'signature.value')
})

test('parseManifest rejects non-hex kid', () => {
  const r = parseManifest({
    manifest:      { site: 's', alg: 'ML-DSA-65', kid: 'not-hex!' },
    signedMessage: 'm',
    signature:     { alg: 'ML-DSA-65', encoding: 'hex', value: 'aa'.repeat(3309) },
    publicKey:     { alg: 'ML-DSA-65', encoding: 'hex', value: 'aa'.repeat(1952), kid: 'aa'.repeat(8) },
  })
  assert.equal(r.ok, false)
  assert.equal(r.error.code, 'invalid_field')
  assert.equal(r.error.field, 'manifest.kid')
})
