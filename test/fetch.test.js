// Tests for src/fetch.js — timeout, byte cap, URL validation. Uses fake fetch.

import { test } from 'node:test'
import assert   from 'node:assert/strict'

import { getJsonBody } from '../src/fetch.js'

test('getJsonBody rejects non-http(s) URLs', async () => {
  const r = await getJsonBody('ftp://example.com/x', { fetchImpl: async () => new Response('') })
  assert.equal(r.ok, false)
  assert.equal(r.error.code, 'invalid_url')
})

test('getJsonBody rejects when no fetch implementation is available', async () => {
  // Save and remove global fetch for this test only.
  const saved = globalThis.fetch
  delete globalThis.fetch
  try {
    const r = await getJsonBody('https://example.com/x')  // no fetchImpl, no global
    assert.equal(r.ok, false)
    assert.equal(r.error.code, 'no_fetch')
  } finally {
    globalThis.fetch = saved
  }
})

test('getJsonBody returns body on 200', async () => {
  const fakeFetch = async () => new Response('hello', { status: 200 })
  const r = await getJsonBody('https://example.com/x', { fetchImpl: fakeFetch })
  assert.equal(r.ok, true)
  assert.equal(r.body, 'hello')
  assert.equal(r.status, 200)
})

test('getJsonBody returns http_status on non-2xx', async () => {
  const fakeFetch = async () => new Response('oops', { status: 503 })
  const r = await getJsonBody('https://example.com/x', { fetchImpl: fakeFetch })
  assert.equal(r.ok, false)
  assert.equal(r.error.code, 'http_status')
  assert.equal(r.error.status, 503)
})

test('getJsonBody returns timeout when fetch throws AbortError', async () => {
  const fakeFetch = async () => {
    const e = new Error('aborted'); e.name = 'AbortError'; throw e
  }
  const r = await getJsonBody('https://example.com/x', { fetchImpl: fakeFetch, timeoutMs: 50 })
  assert.equal(r.ok, false)
  assert.equal(r.error.code, 'timeout')
})

test('getJsonBody returns network code on other thrown errors', async () => {
  const fakeFetch = async () => { throw new Error('econnrefused') }
  const r = await getJsonBody('https://example.com/x', { fetchImpl: fakeFetch })
  assert.equal(r.ok, false)
  assert.equal(r.error.code, 'network')
})

test('getJsonBody respects maxBytes cap', async () => {
  const bigBody = 'x'.repeat(50_000)
  const fakeFetch = async () => new Response(bigBody, { status: 200 })
  const r = await getJsonBody('https://example.com/x', { fetchImpl: fakeFetch, maxBytes: 1000 })
  assert.equal(r.ok, false)
  assert.equal(r.error.code, 'too_large')
})
