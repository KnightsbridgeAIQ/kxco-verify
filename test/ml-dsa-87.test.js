// ML-DSA-87 alongside ML-DSA-65.
//
// The verifier speaks both parameter sets, and the algorithm is bound to the
// key: a manifest's three alg fields must agree, the key and signature must be
// that set's sizes, and verification runs under that set and no other. Every
// ML-DSA-65 manifest that verified before verifies unchanged.
//
// The signer is kxco-post-quantum, a development dependency only. The verifier
// calls the primitive itself, so each case that passes is two implementations
// agreeing on the same parameter set.

import { test }     from 'node:test'
import assert       from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { mlDsa, mlDsa87, fingerprint } from 'kxco-post-quantum'

import { parseManifest, verifyManifest, verifySignature } from '../src/index.js'

// Node 18 has no global Web Crypto
// unless asked for one, and the signer draws its randomness from it.
if (!globalThis.crypto) globalThis.crypto = (await import('node:crypto')).webcrypto

const hex = (b) => Buffer.from(b).toString('hex')
const k65 = mlDsa.ml_dsa65.keygen()
const k87 = mlDsa87.ml_dsa87.keygen()

// A manifest as a publisher serves one, signed under `alg` with `key`.
function publish(alg, key, signer) {
  const kid = fingerprint(key.publicKey)
  const signedMessage = `${kid}.abc1234.production`
  return {
    manifest:  { site: 'example.com', alg, spec: 'NIST FIPS 204', kid, deployment: { git_commit: 'abc1234', env: 'production' } },
    signedMessage,
    signature: { alg, encoding: 'hex', value: signer.sign(key.secretKey, signedMessage) },
    publicKey: { alg, encoding: 'hex', value: hex(key.publicKey), kid },
  }
}
const manifest65 = () => publish('ML-DSA-65', k65, mlDsa)
const manifest87 = () => publish('ML-DSA-87', k87, mlDsa87)
const relabel = (m, alg) => ({ ...m, manifest: { ...m.manifest, alg }, signature: { ...m.signature, alg }, publicKey: { ...m.publicKey, alg } })

// ── parseManifest ───────────────────────────────────────────────────────────

test('parseManifest accepts an ML-DSA-87 manifest at ML-DSA-87 sizes', () => {
  const r = parseManifest(manifest87())
  assert.equal(r.ok, true, JSON.stringify(r.error))
  assert.equal(r.manifest.alg, 'ML-DSA-87')
  assert.equal(r.manifest.publicKeyHex.length, 2592 * 2)
  assert.equal(r.manifest.signatureHex.length, 4627 * 2)
})

test('parseManifest refuses a key and signature of one parameter set labelled as the other', () => {
  for (const [what, m] of [['ML-DSA-65 bytes labelled ML-DSA-87', relabel(manifest65(), 'ML-DSA-87')],
                           ['ML-DSA-87 bytes labelled ML-DSA-65', relabel(manifest87(), 'ML-DSA-65')]]) {
    const r = parseManifest(m)
    assert.equal(r.ok, false, what)
    assert.equal(r.error.code, 'invalid_field', what)
    assert.equal(r.error.field, 'publicKey.value', what)
  }
})

test('parseManifest refuses an ML-DSA-87 key with an ML-DSA-65-sized signature', () => {
  const m = manifest87()
  m.signature.value = manifest65().signature.value
  const r = parseManifest(m)
  assert.equal(r.ok, false)
  assert.equal(r.error.code, 'invalid_field')
  assert.equal(r.error.field, 'signature.value')
})

test('parseManifest refuses a manifest whose alg fields name different parameter sets', () => {
  const sig = manifest87()
  sig.signature.alg = 'ML-DSA-65'
  const key = manifest87()
  key.publicKey.alg = 'ML-DSA-65'
  for (const [m, field] of [[sig, 'signature.alg'], [key, 'publicKey.alg']]) {
    const r = parseManifest(m)
    assert.equal(r.ok, false, field)
    assert.equal(r.error.code, 'invalid_field', field)
    assert.equal(r.error.field, field)
  }
})

test('parseManifest still refuses a parameter set it does not speak', () => {
  for (const alg of ['ML-DSA-44', 'ml-dsa-87', 'ML-DSA-87 ']) {
    const r = parseManifest(relabel(manifest87(), alg))
    assert.equal(r.ok, false, alg)
    assert.equal(r.error.code, 'unsupported_algorithm', alg)
  }
})

// ── verifySignature ─────────────────────────────────────────────────────────

test('verifySignature verifies an ML-DSA-87 signature, the key deciding the set', () => {
  const m = manifest87()
  assert.equal(verifySignature(m.publicKey.value, m.signedMessage, m.signature.value), true)
  assert.equal(verifySignature(m.publicKey.value, m.signedMessage, m.signature.value, 'ML-DSA-87'), true)
  assert.equal(verifySignature(m.publicKey.value, m.signedMessage + 'x', m.signature.value), false)
})

test('verifySignature never checks a key as the other parameter set', () => {
  const m65 = manifest65()
  const m87 = manifest87()
  assert.equal(verifySignature(m87.publicKey.value, m87.signedMessage, m87.signature.value, 'ML-DSA-65'), false)
  assert.equal(verifySignature(m65.publicKey.value, m65.signedMessage, m65.signature.value, 'ML-DSA-87'), false)
  // An ML-DSA-87 signature against an ML-DSA-65 key, and the reverse.
  assert.equal(verifySignature(m65.publicKey.value, m87.signedMessage, m87.signature.value), false)
  assert.equal(verifySignature(m87.publicKey.value, m65.signedMessage, m65.signature.value), false)
})

test('verifySignature throws on an algorithm it does not speak, as it does on malformed hex', () => {
  const m = manifest87()
  for (const alg of ['ML-DSA-44', 'ml-dsa-87', '', null, 87]) {
    assert.throws(() => verifySignature(m.publicKey.value, m.signedMessage, m.signature.value, alg), TypeError, String(alg))
  }
})

test('verifySignature still verifies the live ML-DSA-65 fixtures, with and without naming the set', async () => {
  for (const path of ['fixtures/wallet-attestation.json', 'fixtures/target150-attestation.json']) {
    const body = JSON.parse(await readFile(new URL(`../${path}`, import.meta.url), 'utf-8'))
    assert.equal(verifySignature(body.publicKey.value, body.signedMessage, body.signature.value), true, path)
    assert.equal(verifySignature(body.publicKey.value, body.signedMessage, body.signature.value, 'ML-DSA-65'), true, path)
    assert.equal(verifySignature(body.publicKey.value, body.signedMessage, body.signature.value, 'ML-DSA-87'), false, path)
  }
})

// ── verifyManifest ──────────────────────────────────────────────────────────

test('verifyManifest returns valid for an ML-DSA-87 manifest and reports the algorithm', async () => {
  const r = await verifyManifest(manifest87())
  assert.equal(r.state, 'valid', JSON.stringify(r.error))
  assert.equal(r.algorithm, 'ML-DSA-87')
})

test('verifyManifest returns invalid for an ML-DSA-87 manifest whose signed message was changed', async () => {
  const m = manifest87()
  m.signedMessage += '.tampered'
  const r = await verifyManifest(m)
  assert.equal(r.state, 'invalid')
  assert.equal(r.error.code, 'invalid_signature')
})

test('verifyManifest refuses an ML-DSA-65 manifest relabelled as ML-DSA-87 before any signature check', async () => {
  const r = await verifyManifest(relabel(manifest65(), 'ML-DSA-87'))
  assert.equal(r.state, 'error')
  assert.equal(r.error.kind, 'parse')
})
