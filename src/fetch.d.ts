export interface FetchOk {
  ok: true
  url: string
  status: number
  body: string
}

export interface FetchErr {
  ok: false
  error: {
    kind: 'fetch'
    code: 'no_fetch' | 'invalid_url' | 'timeout' | 'network' | 'http_status' | 'too_large' | 'read'
    message: string
    url?: string
    status?: number
  }
}

export interface GetJsonBodyOpts {
  timeoutMs?: number
  maxBytes?: number
  fetchImpl?: typeof fetch
}

export function getJsonBody(
  url: string,
  opts?: GetJsonBodyOpts,
): Promise<FetchOk | FetchErr>
