// Property-based tests with fast-check.
//
// The example tests beside this file check the verifier against two live
// manifests. These ask the general question. For ANY manifest a publisher signs
// with kxco-post-quantum, does the verifier accept it? For ANY change to what
// the signature covers, and for any input that is not a signed manifest at all,
// does it refuse? fast-check generates the inputs and, when a property breaks,
// shrinks the failing case to the smallest one that still breaks it, so a
// failure arrives as a minimal reproduction rather than a random blob.
//
// The signer is kxco-post-quantum, a development dependency only. The verifier
// shares none of its code, so every case that passes here is also two
// independent implementations agreeing.
//
// No network. verifyUrl is given a local stub in place of fetch, which is the
// `fetchImpl` option the API already takes.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { mlDsa, fingerprint } from 'kxco-post-quantum'
import {
  verifyManifest, verifyUrl, parseManifest, verifySignature,
  computeKid, hexToBytes, bytesToHex, hexEquals,
} from '../src/index.js'

// Node 18, which this repository's CI still runs, has no global Web Crypto
// unless asked for one, and the signer draws its hedging randomness from it.
// With this in place the verifier takes SHA-256 from Web Crypto here, as it
// does on every runtime from Node 20 on; its fallback is left to the example
// tests, which run in a process of their own.
if (!globalThis.crypto) globalThis.crypto = (await import('node:crypto')).webcrypto

// Signing is milliseconds per case, so the properties that sign keep to a
// modest run count; the pure parsing ones run more.
//
// fast-check keeps generated arrays and strings short unless told otherwise,
// whatever maxLength says, so `size: 'max'` is set wherever the length is the
// point: a junk signature of exactly 3309 bytes reaches the real verifier,
// where one of ten bytes stops at the length check.
const RUNS = { numRuns: 30 }

const hex = (bytes) => Buffer.from(bytes).toString('hex')

// A manifest in the shape a publisher serves, signed the way the publishers do
// it: the signature covers `signedMessage`, built from the kid and two
// deployment fields.
function publish(key, { site, commit, env, pinAt = 'kxco-pq-pubkey' }) {
  const kid = fingerprint(key.publicKey)
  const signedMessage = `${kid}.${commit}.${env}`
  return {
    manifest: {
      site,
      alg: 'ML-DSA-65',
      spec: 'NIST FIPS 204',
      kid,
      deployment: { git_commit: commit, env },
      msgFormat: '{kid}.{deployment.git_commit}.{deployment.env}',
    },
    signedMessage,
    signature: { alg: 'ML-DSA-65', encoding: 'hex', value: mlDsa.sign(key.secretKey, signedMessage) },
    publicKey: { alg: 'ML-DSA-65', encoding: 'hex', value: hex(key.publicKey), kid, pinAt },
  }
}

const clone = (value) => JSON.parse(JSON.stringify(value))

// Flip one bit of a hex-encoded value, so the bytes are certain to differ.
function flipBit(hexValue, at, bit) {
  const bytes = Buffer.from(hexValue, 'hex')
  bytes[at % bytes.length] ^= 1 << (bit % 8)
  return bytes.toString('hex')
}

// Change one hex digit to a different value, not merely a different case.
function changeDigit(hexValue, at, by) {
  const i = at % hexValue.length
  const next = ((parseInt(hexValue[i], 16) + 1 + (by % 15)) % 16).toString(16)
  return hexValue.slice(0, i) + next + hexValue.slice(i + 1)
}

const master = fc.uint8Array({ minLength: 16, maxLength: 64 })
const info = fc.string({ minLength: 1, maxLength: 40 })
const site = fc.string({ minLength: 1, maxLength: 60, unit: 'grapheme' })
const commit = fc.oneof(fc.stringMatching(/^[0-9a-f]{40}$/), fc.string({ maxLength: 40, unit: 'binary', size: 'medium' }))
const env = fc.string({ maxLength: 20, unit: 'grapheme' })
const notString = fc.anything({ maxDepth: 1 }).filter((v) => typeof v !== 'string')

// Two fixed keys: one publishes, the other plays a different signer.
const signer = mlDsa.keypairFromMaster(new Uint8Array(32).fill(7), 'kxco-verify-property-tests-v1')
const other = mlDsa.keypairFromMaster(new Uint8Array(32).fill(9), 'kxco-verify-property-tests-v1')

test('the harness fails a property that is false', () => {
  assert.throws(() => fc.assert(fc.property(fc.integer(), (n) => n + 1 === n), { numRuns: 10 }))
})

test('hex helpers: any bytes round-trip, in either case, and the encoding is lowercase', () => {
  fc.assert(fc.property(fc.uint8Array({ maxLength: 3000, size: 'max' }), (bytes) => {
    const h = bytesToHex(bytes)
    return /^[0-9a-f]*$/.test(h) && h.length === bytes.length * 2 && h === hex(bytes) &&
      Buffer.from(hexToBytes(h)).equals(Buffer.from(bytes)) &&
      Buffer.from(hexToBytes(h.toUpperCase())).equals(Buffer.from(bytes))
  }), { numRuns: 300 })
})

test('hexToBytes: anything but an even-length run of hex digits is refused with a TypeError', () => {
  const odd = fc.string({ maxLength: 200, unit: 'binary', size: 'medium' }).filter((s) => s.length % 2 === 1)
  // Even length, with at least one character that is not a hex digit. Placing
  // it inside otherwise valid hex reaches the second digit of a byte, where a
  // decoder that reads a prefix of each pair would accept it.
  const nonHex = fc.string({ minLength: 1, maxLength: 1, unit: 'binary' }).filter((c) => !/[0-9a-fA-F]/.test(c))
  const evenBad = fc.oneof(
    fc.tuple(fc.stringMatching(/^[0-9a-fA-F]{0,40}$/), nonHex, fc.stringMatching(/^[0-9a-fA-F]{0,40}$/))
      .map(([a, c, b]) => a + c + b)
      .map((s) => (s.length % 2 === 0 ? s : s + '0')),
    fc.string({ maxLength: 200, unit: 'binary', size: 'medium' })
      .filter((s) => s.length % 2 === 0 && !/^[0-9a-fA-F]*$/.test(s)),
  )
  fc.assert(fc.property(fc.oneof(odd, notString), (input) => {
    assert.throws(() => hexToBytes(input), (e) => e instanceof TypeError && /even length/.test(e.message))
    return true
  }), { numRuns: 300 })
  fc.assert(fc.property(evenBad, (input) => {
    assert.throws(() => hexToBytes(input), (e) => e instanceof TypeError && /malformed hex/.test(e.message))
    return true
  }), { numRuns: 300 })
})

test('hexEquals: agrees with string equality, and is false for anything that is not a string', () => {
  const pair = fc.oneof(
    fc.tuple(fc.string({ maxLength: 40, unit: 'binary' }), fc.string({ maxLength: 40, unit: 'binary' })),
    fc.string({ maxLength: 40, unit: 'binary' }).map((s) => [s, s]),
    // Two kids a single digit apart, the case a comparison is most likely to get wrong.
    fc.tuple(fc.stringMatching(/^[0-9a-f]{16}$/), fc.nat(), fc.nat()).map(([s, at, by]) => [s, changeDigit(s, at, by)]),
  )
  fc.assert(fc.property(pair, notString, ([a, b], junk) => {
    return hexEquals(a, b) === (a === b) && hexEquals(a, junk) === false && hexEquals(junk, a) === false
  }), { numRuns: 500 })
})

test('computeKid: agrees with kxco-post-quantum fingerprint for any key bytes, given as bytes or hex', async () => {
  const keyBytes = fc.oneof(
    fc.uint8Array({ minLength: 1952, maxLength: 1952 }),
    fc.uint8Array({ minLength: 1, maxLength: 2600, size: 'max' }),
  )
  await fc.assert(fc.asyncProperty(keyBytes, async (bytes) => {
    const expected = fingerprint(bytes)
    return await computeKid(bytes) === expected &&
      await computeKid(hex(bytes)) === expected &&
      await computeKid(hex(bytes).toUpperCase()) === expected
  }), { numRuns: 200 })
})

test('verifyManifest: a manifest signed with kxco-post-quantum verifies, for any key, site and deployment', async () => {
  await fc.assert(fc.asyncProperty(master, info, site, commit, env, async (m, i, s, c, e) => {
    const key = mlDsa.keypairFromMaster(m, i)
    const r = await verifyManifest(JSON.stringify(publish(key, { site: s, commit: c, env: e })))
    return r.state === 'valid' &&
      r.error === undefined &&
      r.algorithm === 'ML-DSA-65' &&
      r.manifestKid === fingerprint(key.publicKey) &&
      r.site === s &&
      r.deployment.git_commit === c &&
      r.deployment.env === e
  }), { numRuns: 20 })
})

test('verifyManifest: any change to what the signature covers makes the manifest invalid', async () => {
  const change = fc.record({
    field: fc.constantFrom(
      'signedMessage', 'signature', 'publicKey', 'publicKeyAndKids',
      'manifestKid', 'publicKeyKid', 'otherSigner',
    ),
    at: fc.nat(),
    by: fc.nat(),
    insert: fc.string({ minLength: 1, maxLength: 8 }),
  })
  await fc.assert(fc.asyncProperty(commit, env, change, async (c, e, { field, at, by, insert }) => {
    const body = publish(signer, { site: 'example.test', commit: c, env: e })
    switch (field) {
      case 'signedMessage': {
        const i = at % (body.signedMessage.length + 1)
        body.signedMessage = body.signedMessage.slice(0, i) + insert + body.signedMessage.slice(i)
        break
      }
      case 'signature':
        body.signature.value = flipBit(body.signature.value, at, by)
        break
      case 'publicKey':
        body.publicKey.value = flipBit(body.publicKey.value, at, by)
        break
      case 'publicKeyAndKids': {
        // A substituted key with both kids brought into line with it: the
        // internal consistency check passes, so the signature has to fail.
        body.publicKey.value = flipBit(body.publicKey.value, at, by)
        const kid = fingerprint(Buffer.from(body.publicKey.value, 'hex'))
        body.manifest.kid = kid
        body.publicKey.kid = kid
        break
      }
      case 'manifestKid':
        body.manifest.kid = changeDigit(body.manifest.kid, at, by)
        break
      case 'publicKeyKid':
        body.publicKey.kid = changeDigit(body.publicKey.kid, at, by)
        break
      case 'otherSigner':
        body.signature.value = mlDsa.sign(other.secretKey, body.signedMessage)
        break
    }
    const r = await verifyManifest(JSON.stringify(body))
    return r.state === 'invalid' && typeof r.error?.code === 'string'
  }), { numRuns: 40 })
})

test('verifyManifest: a signed field replaced by any other JSON value is refused, never verified', async () => {
  const base = publish(signer, { site: 'example.test', commit: 'c0ffee', env: 'production' })
  const paths = [
    ['signedMessage'], ['signature'], ['publicKey'], ['manifest'],
    ['signature', 'value'], ['publicKey', 'value'], ['manifest', 'kid'], ['publicKey', 'kid'],
    ['manifest', 'alg'], ['signature', 'alg'], ['publicKey', 'alg'],
  ]
  await fc.assert(fc.asyncProperty(fc.constantFrom(...paths), fc.jsonValue(), async (path, value) => {
    const original = path.reduce((o, k) => o[k], base)
    const same = typeof value === 'string' && typeof original === 'string'
      ? value.toLowerCase() === original.toLowerCase()
      : JSON.stringify(value) === JSON.stringify(original)
    fc.pre(!same)
    const body = clone(base)
    const parent = path.slice(0, -1).reduce((o, k) => o[k], body)
    parent[path[path.length - 1]] = value
    const r = await verifyManifest(JSON.stringify(body))
    return (r.state === 'invalid' || r.state === 'error') && typeof r.error?.kind === 'string'
  }), { numRuns: 400 })
})

test('verifyManifest: arbitrary text never verifies, and is refused with an error result rather than a throw', async () => {
  const text = fc.oneof(
    fc.string({ maxLength: 400, unit: 'binary', size: 'medium' }),
    fc.json(),
    fc.jsonValue({ maxDepth: 2 }).map((v) => JSON.stringify(v)),
  )
  await fc.assert(fc.asyncProperty(text, async (t) => {
    const r = await verifyManifest(t)
    return (r.state === 'error' || r.state === 'invalid') && typeof r.error?.code === 'string'
  }), { numRuns: 500 })
})

test('parseManifest: any JSON value that is not a signed manifest, as an object or as text, and text that is not JSON, is refused with a parse error', () => {
  const notJson = fc.string({ maxLength: 300, unit: 'binary', size: 'medium' }).filter((s) => {
    try { JSON.parse(s); return false } catch { return true }
  })
  const value = fc.oneof(fc.object(), fc.jsonValue({ maxDepth: 2 }))
  fc.assert(fc.property(fc.oneof(value, value.map((v) => JSON.stringify(v)), notJson), (input) => {
    const isText = typeof input === 'string'
    let isJson = false
    if (isText) try { JSON.parse(input); isJson = true } catch { /* not JSON */ }
    const r = parseManifest(input)
    return r.ok === false &&
      r.error.kind === 'parse' &&
      typeof r.error.code === 'string' &&
      (!isText || isJson || r.error.code === 'invalid_json')
  }), { numRuns: 500 })
})

test('verifySignature: fails closed on an arbitrary signature', () => {
  const publicKeyHex = hex(signer.publicKey)
  const message = fc.oneof(fc.uint8Array({ maxLength: 512 }), fc.string({ maxLength: 256 }))
  const junk = fc.oneof(
    fc.uint8Array({ minLength: 3309, maxLength: 3309 }),
    fc.uint8Array({ maxLength: 4000, size: 'max' }),
  )
  fc.assert(fc.property(message, junk, fc.string({ maxLength: 200, unit: 'binary', size: 'medium' }), (msg, junk, text) => {
    if (verifySignature(publicKeyHex, msg, junk) !== false) return false
    if (verifySignature(publicKeyHex, msg, bytesToHex(junk)) !== false) return false
    // Text that is not an even run of hex is refused by the hex decoder with
    // its own TypeError; anything it does decode must still fail to verify.
    try {
      return verifySignature(publicKeyHex, msg, text) === false
    } catch (e) {
      return e instanceof TypeError && /even length|malformed hex/.test(e.message)
    }
  }), RUNS)
})

test('verifyUrl: whatever JSON the attestation or the live key endpoint serves, the result is a state, never a throw', async () => {
  const base = publish(signer, { site: 'example.test', commit: 'c0ffee', env: 'production' })
  const attestationUrl = 'https://example.test/api/attestation'
  const pubkeyUrl = new URL(base.publicKey.pinAt, attestationUrl).toString()
  const served = fc.oneof(
    fc.jsonValue({ maxDepth: 2 }),
    fc.string({ maxLength: 80, unit: 'binary' }).map((publicKey) => ({ publicKey })),
    fc.string({ maxLength: 80, unit: 'binary' }).map((value) => ({ value })),
  )
  await fc.assert(fc.asyncProperty(fc.boolean(), served, async (atAttestation, body) => {
    const fetchImpl = async (url) => {
      if (url === attestationUrl) return new Response(JSON.stringify(atAttestation ? body : base), { status: 200 })
      if (url === pubkeyUrl) return new Response(JSON.stringify(body), { status: 200 })
      throw new Error(`unexpected fetch: ${url}`)
    }
    const r = await verifyUrl(attestationUrl, { fetchImpl })
    return atAttestation
      ? r.state === 'error' && r.error.kind === 'parse'
      : ['valid', 'rotated'].includes(r.state) && (r.state === 'rotated' || r.error === undefined || r.error.soft === true)
  }), { numRuns: 200 })
})

test('verifyUrl: the live key decides between valid and rotated, wherever pinAt points', async () => {
  const base = publish(signer, { site: 'example.test', commit: 'c0ffee', env: 'production' })
  const pinAt = fc.oneof(
    fc.stringMatching(/^[a-z0-9-]{1,24}$/),
    fc.stringMatching(/^\/\.well-known\/[a-z0-9-]{1,24}$/),
  )
  await fc.assert(fc.asyncProperty(
    fc.stringMatching(/^[a-z0-9]{1,12}$/), fc.stringMatching(/^[a-z0-9-]{1,24}$/), pinAt, fc.boolean(), fc.boolean(),
    async (host, path, pin, rotated, valueField) => {
      const attestationUrl = `https://${host}.example/api/${path}`
      const pubkeyUrl = new URL(pin, attestationUrl).toString()
      const body = clone(base)
      body.publicKey.pinAt = pin
      const live = rotated ? other : signer
      const liveBody = valueField ? { value: hex(live.publicKey) } : { publicKey: hex(live.publicKey) }
      const fetchImpl = async (url) => {
        if (url === attestationUrl) return new Response(JSON.stringify(body), { status: 200 })
        if (url === pubkeyUrl) return new Response(JSON.stringify(liveBody), { status: 200 })
        throw new Error(`unexpected fetch: ${url}`)
      }
      const r = await verifyUrl(attestationUrl, { fetchImpl })
      if (r.pubkeyUrl !== pubkeyUrl || r.livePubkeyKid !== fingerprint(live.publicKey)) return false
      return rotated
        ? r.state === 'rotated' && r.error.code === 'live_kid_mismatch'
        : r.state === 'valid' && r.error === undefined
    },
  ), { numRuns: 50 })
})
