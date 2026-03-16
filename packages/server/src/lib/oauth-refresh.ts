/**
 * OAuth token refresh — shared between core proxy and managed OAuth flows.
 * Pure HTTP logic with no infrastructure dependencies.
 */
import { isRecord } from './utils'

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split('.')
  let current: unknown = obj
  for (const part of parts) {
    if (!isRecord(current)) return undefined
    current = current[part]
  }
  return current
}

async function parseTokenPayload(tokenRes: Response): Promise<Record<string, unknown>> {
  const text = await tokenRes.text()
  const contentType = tokenRes.headers.get('content-type') ?? ''

  if (contentType.includes('application/json') || text.trim().startsWith('{')) {
    const parsed = JSON.parse(text)
    return isRecord(parsed) ? parsed : {}
  }

  const params = new URLSearchParams(text)
  const payload: Record<string, unknown> = {}
  for (const [key, value] of params.entries()) {
    payload[key] = value
  }
  return payload
}

function resolveExpiresAt(tokenData: Record<string, unknown>): string | undefined {
  const expiresAtRaw = tokenData.expires_at
  if (typeof expiresAtRaw === 'string') {
    const parsed = new Date(expiresAtRaw)
    if (!Number.isNaN(parsed.getTime())) return parsed.toISOString()
  }

  const expiresInRaw = tokenData.expires_in
  if (typeof expiresInRaw === 'number' && Number.isFinite(expiresInRaw)) {
    return new Date(Date.now() + expiresInRaw * 1000).toISOString()
  }
  if (typeof expiresInRaw === 'string') {
    const n = Number.parseInt(expiresInRaw, 10)
    if (!Number.isNaN(n)) {
      return new Date(Date.now() + n * 1000).toISOString()
    }
  }

  return undefined
}

export async function refreshOAuthToken(params: {
  tokenUrl: string
  refreshToken: string
  clientId: string
  clientSecret?: string
  scopes?: string
  authConfig?: Record<string, string>
}) {
  const tokenBody: Record<string, string> = {
    grant_type: 'refresh_token',
    refresh_token: params.refreshToken,
  }

  if (params.scopes) {
    tokenBody.scope = params.scopes
  }

  const tokenHeaders: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  }

  if (params.authConfig?.token_auth === 'basic' && params.clientSecret) {
    tokenHeaders.Authorization = `Basic ${btoa(`${params.clientId}:${params.clientSecret}`)}`
  } else {
    tokenBody.client_id = params.clientId
    if (params.clientSecret) {
      tokenBody.client_secret = params.clientSecret
    }
  }

  if (params.authConfig?.token_accept) {
    tokenHeaders.Accept = params.authConfig.token_accept
  }

  const tokenRes = await fetch(params.tokenUrl, {
    method: 'POST',
    headers: tokenHeaders,
    body: new URLSearchParams(tokenBody).toString(),
  })

  if (!tokenRes.ok) {
    const text = await tokenRes.text()
    throw new Error(`Token refresh failed: ${text}`)
  }

  const tokenData = await parseTokenPayload(tokenRes)
  const accessToken =
    (params.authConfig?.token_path
      ? getNestedValue(tokenData, params.authConfig.token_path)
      : tokenData.access_token)
  const resolvedAccessToken = asString(accessToken)

  if (!resolvedAccessToken) {
    throw new Error('No access token in refresh response')
  }

  const refreshToken =
    (params.authConfig?.refresh_token_path
      ? getNestedValue(tokenData, params.authConfig.refresh_token_path)
      : tokenData.refresh_token)

  return {
    accessToken: resolvedAccessToken,
    refreshToken: asString(refreshToken) ?? params.refreshToken,
    expiresAt: resolveExpiresAt(tokenData),
  }
}
