// Tests for the top-level verifyManifest + verifyUrl orchestrator.
//
// verifyUrl is exercised against an in-process fake `fetch` so the suite has
// no network dependency. Live smoke against real production endpoints lives
// in scripts/smoke.js, not in the test suite.

import { test }     from 'node:test'
import assert       from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

import { verifyManifest, verifyUrl } from '../src/index.js'

const FIXTURES = {
  wallet: {
    attestationUrl: 'https://chain.kxco.ai/wallet/api/.well-known/kxco-pq-attestation',
    pubkeyUrl:      'https://chain.kxco.ai/wallet/api/.well-known/kxco-pq-pubkey',
    attestationPath: 'fixtures/wallet-attestation.json',
    pubkeyPath:      'fixtures/wallet-pubkey.json',
  },
  target150: {
    attestationUrl: 'https://www.target150.com/api/attestation',
    pubkeyUrl:      'https://www.target150.com/.well-known/target150-pq-pubkey',
    attestationPath: 'fixtures/target150-attestation.json',
    pubkeyPath:      'fixtures/target150-pubkey.json',
  },
}

async function loadFixtures() {
  const out = {}
  for (const [name, f] of Object.entries(FIXTURES)) {
    out[name] = {
      ...f,
      attestationBody: await readFile(new URL(`../${f.attestationPath}`,  import.meta.url), 'utf-8'),
      pubkeyBody:      await readFile(new URL(`../${f.pubkeyPath}`,       import.meta.url), 'utf-8'),
    }
  }
  return out
}

function fakeFetchOk(body, status = 200) {
  return new Response(body, { status, headers: { 'Content-Type': 'application/json' } })
}

// verifyManifest
for (const name of ['wallet', 'target150']) {
  test(`verifyManifest returns state="valid" for the ${name} fixture`, async () => {
    const fxs = await loadFixtures()
    const r = await verifyManifest(fxs[name].attestationBody)
    assert.equal(r.state, 'valid', JSON.stringify(r.error))
    assert.equal(r.algorithm, 'ML-DSA-65')
    assert.equal(r.manifestKid.length, 16)
    assert.ok(r.manifestRaw)
  })
}

test('verifyManifest returns state="invalid" when the signature is tampered with', async () => {
  const fxs = await loadFixtures()
  const obj = JSON.parse(fxs.wallet.attestationBody)
  obj.signature.value = (((parseInt(obj.signature.value.slice(0, 2), 16) ^ 0xff) & 0xff)).toString(16).padStart(2, '0') + obj.signature.value.slice(2)
  const r = await verifyManifest(obj)
  assert.equal(r.state, 'invalid')
  assert.equal(r.error.kind, 'signature')
})

test('verifyManifest returns state="invalid" when the kid does not match the SHA-256 of the pubkey', async () => {
  const fxs = await loadFixtures()
  const obj = JSON.parse(fxs.wallet.attestationBody)
  obj.manifest.kid = 'ffffffffffffffff'
  obj.publicKey.kid = 'ffffffffffffffff'
  const r = await verifyManifest(obj)
  assert.equal(r.state, 'invalid')
  assert.equal(r.error.code, 'kid_mismatch_internal')
})

test('verifyManifest returns state="error" when JSON is malformed', async () => {
  const r = await verifyManifest('{nope')
  assert.equal(r.state, 'error')
  assert.equal(r.error.kind, 'parse')
})

// verifyUrl with fake fetch
for (const name of ['wallet', 'target150']) {
  test(`verifyUrl returns state="valid" for ${name} (live pubkey matches manifest kid)`, async () => {
    const fxs = await loadFixtures()
    const f = fxs[name]
    const fakeFetch = async (url) => {
      if (url === f.attestationUrl) return fakeFetchOk(f.attestationBody)
      if (url === f.pubkeyUrl)      return fakeFetchOk(f.pubkeyBody)
      throw new Error(`unexpected fetch: ${url}`)
    }
    const r = await verifyUrl(f.attestationUrl, { fetchImpl: fakeFetch })
    assert.equal(r.state, 'valid', JSON.stringify(r.error))
    assert.equal(r.attestationUrl, f.attestationUrl)
    assert.equal(r.pubkeyUrl,      f.pubkeyUrl)
    assert.equal(r.livePubkeyKid,  r.manifestKid)
  })

  test(`verifyUrl returns state="rotated" for ${name} when live pubkey serves a different kid`, async () => {
    const fxs = await loadFixtures()
    const f = fxs[name]
    // Build a fake pubkey body whose kid differs from the manifest's.
    // Easiest: keep the wallet pubkey body but flip a byte of the publicKey,
    // which will recompute to a different kid.
    const pkObj = JSON.parse(f.pubkeyBody)
    const pkField = typeof pkObj.publicKey === 'string' ? 'publicKey' : 'value'
    pkObj[pkField] = '00' + pkObj[pkField].slice(2)
    const tamperedPubkeyBody = JSON.stringify(pkObj)
    const fakeFetch = async (url) => {
      if (url === f.attestationUrl) return fakeFetchOk(f.attestationBody)
      if (url === f.pubkeyUrl)      return fakeFetchOk(tamperedPubkeyBody)
      throw new Error(`unexpected fetch: ${url}`)
    }
    const r = await verifyUrl(f.attestationUrl, { fetchImpl: fakeFetch })
    assert.equal(r.state, 'rotated', JSON.stringify(r.error))
    assert.notEqual(r.livePubkeyKid, r.manifestKid)
    assert.equal(r.error.code, 'live_kid_mismatch')
  })

  test(`verifyUrl returns state="valid" with a soft error when the live pubkey endpoint is unreachable`, async () => {
    const fxs = await loadFixtures()
    const f = fxs[name]
    const fakeFetch = async (url) => {
      if (url === f.attestationUrl) return fakeFetchOk(f.attestationBody)
      if (url === f.pubkeyUrl)      return new Response('nope', { status: 503 })
      throw new Error(`unexpected fetch: ${url}`)
    }
    const r = await verifyUrl(f.attestationUrl, { fetchImpl: fakeFetch })
    assert.equal(r.state, 'valid')
    assert.equal(r.error.kind, 'fetch')
    assert.equal(r.error.soft, true)
  })
}

test('verifyUrl returns state="error" when the attestation URL itself is unreachable', async () => {
  const fakeFetch = async () => new Response('boom', { status: 500 })
  const r = await verifyUrl('https://example.invalid/api/attestation', { fetchImpl: fakeFetch })
  assert.equal(r.state, 'error')
  assert.equal(r.error.kind, 'fetch')
})

test('verifyUrl returns "valid" with soft error when manifest omits pinAt', async () => {
  const fxs = await loadFixtures()
  const f = fxs.wallet
  const obj = JSON.parse(f.attestationBody)
  delete obj.publicKey.pinAt
  const fakeFetch = async (url) => {
    if (url === f.attestationUrl) return fakeFetchOk(JSON.stringify(obj))
    throw new Error(`unexpected fetch: ${url}`)
  }
  const r = await verifyUrl(f.attestationUrl, { fetchImpl: fakeFetch })
  assert.equal(r.state, 'valid')
  assert.equal(r.livePubkeyKid, undefined)
  assert.equal(r.error, undefined)
})

test('verifyUrl returns "invalid" when manifest.publicKey.pinAt is unresolvable', async () => {
  const fxs = await loadFixtures()
  const f = fxs.wallet
  const obj = JSON.parse(f.attestationBody)
  obj.publicKey.pinAt = 'http://[unparseable url]'
  const fakeFetch = async (url) => {
    if (url === f.attestationUrl) return fakeFetchOk(JSON.stringify(obj))
    throw new Error(`unexpected fetch: ${url}`)
  }
  const r = await verifyUrl(f.attestationUrl, { fetchImpl: fakeFetch })
  assert.equal(r.state, 'invalid')
  assert.equal(r.error.code, 'invalid_pinAt')
})

test('verifyUrl returns "valid" with soft error when live pubkey body is malformed JSON', async () => {
  const fxs = await loadFixtures()
  const f = fxs.wallet
  const fakeFetch = async (url) => {
    if (url === f.attestationUrl) return fakeFetchOk(f.attestationBody)
    if (url === f.pubkeyUrl)      return fakeFetchOk('{not json')
    throw new Error(`unexpected fetch: ${url}`)
  }
  const r = await verifyUrl(f.attestationUrl, { fetchImpl: fakeFetch })
  assert.equal(r.state, 'valid')
  assert.equal(r.error.code, 'invalid_live_pubkey_json')
  assert.equal(r.error.soft, true)
})

test('verifyUrl returns "valid" with soft error when live pubkey body has no publicKey field', async () => {
  const fxs = await loadFixtures()
  const f = fxs.wallet
  const fakeFetch = async (url) => {
    if (url === f.attestationUrl) return fakeFetchOk(f.attestationBody)
    if (url === f.pubkeyUrl)      return fakeFetchOk(JSON.stringify({ alg: 'ML-DSA-65' }))
    throw new Error(`unexpected fetch: ${url}`)
  }
  const r = await verifyUrl(f.attestationUrl, { fetchImpl: fakeFetch })
  assert.equal(r.state, 'valid')
  assert.equal(r.error.code, 'live_pubkey_missing')
  assert.equal(r.error.soft, true)
})

test('verifyUrl honours skipLivePubkey — does not fetch the well-known endpoint', async () => {
  const fxs = await loadFixtures()
  const f = fxs.wallet
  let pkFetched = false
  const fakeFetch = async (url) => {
    if (url === f.attestationUrl) return fakeFetchOk(f.attestationBody)
    if (url === f.pubkeyUrl) { pkFetched = true; throw new Error('should not be called') }
    throw new Error(`unexpected fetch: ${url}`)
  }
  const r = await verifyUrl(f.attestationUrl, { fetchImpl: fakeFetch, skipLivePubkey: true })
  assert.equal(r.state, 'valid')
  assert.equal(pkFetched, false)
  assert.equal(r.livePubkeyKid, undefined)
})
