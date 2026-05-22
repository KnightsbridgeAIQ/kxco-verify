// Tests for verify.js — kid math, hex helpers, signature verification against the live fixtures.

import { test }     from 'node:test'
import assert       from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

import {
  hexToBytes,
  bytesToHex,
  utf8,
  computeKid,
  verifySignature,
  hexEquals,
} from '../src/verify.js'

test('hexToBytes / bytesToHex round-trip', () => {
  const hex = 'deadbeef00ff42'
  const b   = hexToBytes(hex)
  assert.equal(b.length, 7)
  assert.equal(bytesToHex(b), hex)
})

test('hexToBytes rejects odd-length input', () => {
  assert.throws(() => hexToBytes('abc'), /even length/)
})

test('hexToBytes rejects non-hex input', () => {
  assert.throws(() => hexToBytes('zz'), /malformed hex/)
})

test('utf8 encodes ascii correctly', () => {
  const b = utf8('abc')
  assert.deepEqual([...b], [97, 98, 99])
})

test('hexEquals matches identical strings, rejects mismatches', () => {
  assert.equal(hexEquals('abcd', 'abcd'), true)
  assert.equal(hexEquals('abcd', 'abce'), false)
  assert.equal(hexEquals('abcd', 'abc'), false)
  assert.equal(hexEquals('abcd', null), false)
})

test('computeKid produces a 16-char lowercase hex string', async () => {
  const kid = await computeKid('00'.repeat(1952))
  assert.equal(kid.length, 16)
  assert.match(kid, /^[0-9a-f]{16}$/)
})

test('computeKid is deterministic', async () => {
  const a = await computeKid('aa'.repeat(1952))
  const b = await computeKid('aa'.repeat(1952))
  assert.equal(a, b)
})

test('computeKid differs for different inputs', async () => {
  const a = await computeKid('aa'.repeat(1952))
  const b = await computeKid('bb'.repeat(1952))
  assert.notEqual(a, b)
})

for (const path of ['fixtures/wallet-attestation.json', 'fixtures/target150-attestation.json']) {
  test(`computeKid matches the manifest's declared kid for ${path}`, async () => {
    const body = JSON.parse(await readFile(new URL(`../${path}`, import.meta.url), 'utf-8'))
    const recomputed = await computeKid(body.publicKey.value)
    assert.equal(recomputed, body.manifest.kid)
  })

  test(`verifySignature returns true for the live ${path} signature`, async () => {
    const body = JSON.parse(await readFile(new URL(`../${path}`, import.meta.url), 'utf-8'))
    const ok = verifySignature(body.publicKey.value, body.signedMessage, body.signature.value)
    assert.equal(ok, true)
  })

  test(`verifySignature returns false if the signed message is altered for ${path}`, async () => {
    const body = JSON.parse(await readFile(new URL(`../${path}`, import.meta.url), 'utf-8'))
    const ok = verifySignature(body.publicKey.value, body.signedMessage + 'tamper', body.signature.value)
    assert.equal(ok, false)
  })

  test(`verifySignature returns false if a signature byte is flipped for ${path}`, async () => {
    const body = JSON.parse(await readFile(new URL(`../${path}`, import.meta.url), 'utf-8'))
    // Flip the first byte.
    const tampered = (((parseInt(body.signature.value.slice(0, 2), 16) ^ 0xff) & 0xff)).toString(16).padStart(2, '0') + body.signature.value.slice(2)
    const ok = verifySignature(body.publicKey.value, body.signedMessage, tampered)
    assert.equal(ok, false)
  })
}
