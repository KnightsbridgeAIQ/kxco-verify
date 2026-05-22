// Network fetching. Browser-safe (uses global `fetch`), with a hard timeout
// per request via AbortController so a slow target site cannot hang the
// verifier. Returns either { ok: true, body, url, status } or
// { ok: false, error: { kind: 'fetch', code, message } }.

const DEFAULT_TIMEOUT_MS = 3000
const DEFAULT_MAX_BYTES  = 200_000   // attestation manifests are ~11KB; cap at 200KB

/**
 * @typedef {Object} FetchOk
 * @property {true}    ok
 * @property {string}  url
 * @property {number}  status
 * @property {string}  body
 *
 * @typedef {Object} FetchErr
 * @property {false}  ok
 * @property {{ kind: 'fetch', code: string, message: string, url?: string, status?: number }} error
 */

/**
 * GET a URL with a timeout, returning the body as a UTF-8 string. Caps the
 * response at maxBytes to defend against memory blow-ups from a hostile
 * target. Does NOT throw — always returns a tagged result.
 *
 * @param {string} url
 * @param {{ timeoutMs?: number, maxBytes?: number, fetchImpl?: typeof fetch }} [opts]
 * @returns {Promise<FetchOk | FetchErr>}
 */
export async function getJsonBody(url, opts = {}) {
  const timeoutMs = typeof opts.timeoutMs === 'number' ? opts.timeoutMs : DEFAULT_TIMEOUT_MS
  const maxBytes  = typeof opts.maxBytes  === 'number' ? opts.maxBytes  : DEFAULT_MAX_BYTES
  const f         = opts.fetchImpl || globalThis.fetch

  if (typeof f !== 'function') {
    return errFetch_('no_fetch', 'global fetch() not available; pass opts.fetchImpl', { url })
  }
  if (typeof url !== 'string' || (!url.startsWith('http://') && !url.startsWith('https://'))) {
    return errFetch_('invalid_url', 'url must be an absolute http(s) URL', { url })
  }

  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  let res
  try {
    res = await f(url, { signal: ctrl.signal, redirect: 'follow', headers: { 'Accept': 'application/json' } })
  } catch (err) {
    clearTimeout(timer)
    const code = err && err.name === 'AbortError' ? 'timeout' : 'network'
    return errFetch_(code, code === 'timeout' ? `fetch timed out after ${timeoutMs}ms` : `network error: ${err.message}`, { url })
  }
  clearTimeout(timer)

  if (!res.ok) {
    return errFetch_('http_status', `HTTP ${res.status}`, { url, status: res.status })
  }

  // Read with a byte cap to prevent OOM on hostile responses.
  let body
  try {
    body = await readWithCap_(res, maxBytes)
  } catch (err) {
    if (err && err.code === 'too_large') {
      return errFetch_('too_large', `response exceeded ${maxBytes} bytes`, { url, status: res.status })
    }
    return errFetch_('read', `failed to read response body: ${err.message}`, { url, status: res.status })
  }

  return { ok: true, url, status: res.status, body }
}

async function readWithCap_(res, maxBytes) {
  if (!res.body || typeof res.body.getReader !== 'function') {
    // Fallback for environments without streams: read the whole text, check size.
    const text = await res.text()
    if (text.length > maxBytes * 4) { const e = new Error('too large'); e.code = 'too_large'; throw e }
    return text
  }
  const reader = res.body.getReader()
  const chunks = []
  let total = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.length
    if (total > maxBytes) {
      try { await reader.cancel() } catch {}
      const e = new Error('too large'); e.code = 'too_large'; throw e
    }
    chunks.push(value)
  }
  const merged = new Uint8Array(total)
  let off = 0
  for (const c of chunks) { merged.set(c, off); off += c.length }
  return new TextDecoder('utf-8').decode(merged)
}

function errFetch_(code, message, extra = {}) {
  return { ok: false, error: { kind: 'fetch', code, message, ...extra } }
}
