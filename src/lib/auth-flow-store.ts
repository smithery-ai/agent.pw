import type { Redis } from '@upstash/redis'

export interface AuthFlow {
  id: string
  service: string
  method: string
  status: 'pending' | 'completed'
  codeVerifier?: string
  orgId?: string
  oauthSource?: 'managed' | 'byo'
  wardenToken?: string
  identity?: string
  createdAt: string
  expiresAt: string
}

function key(id: string) {
  return `flow:${id}`
}

export async function createAuthFlow(
  redis: Redis,
  data: {
    id: string
    service: string
    method: string
    codeVerifier?: string
    orgId?: string
    oauthSource?: 'managed' | 'byo'
    expiresAt: Date
  },
) {
  const ttl = Math.max(1, Math.ceil((data.expiresAt.getTime() - Date.now()) / 1000))
  const flow: AuthFlow = {
    id: data.id,
    service: data.service,
    method: data.method,
    status: 'pending',
    codeVerifier: data.codeVerifier,
    orgId: data.orgId,
    oauthSource: data.oauthSource,
    createdAt: new Date().toISOString(),
    expiresAt: data.expiresAt.toISOString(),
  }
  await redis.set(key(data.id), JSON.stringify(flow), { ex: ttl })
}

export async function getAuthFlow(redis: Redis, id: string) {
  const raw = await redis.get<string>(key(id))
  if (!raw) return null
  const flow: AuthFlow = typeof raw === 'string' ? JSON.parse(raw) : raw
  // Check expiry (belt-and-suspenders with TTL)
  if (new Date(flow.expiresAt) < new Date()) return null
  return flow
}

export async function completeAuthFlow(
  redis: Redis,
  id: string,
  data: { wardenToken: string; identity: string; orgId: string },
) {
  const flow = await getAuthFlow(redis, id)
  if (!flow) return
  const updated: AuthFlow = {
    ...flow,
    status: 'completed',
    wardenToken: data.wardenToken,
    identity: data.identity,
    orgId: data.orgId,
  }
  const remainingTtl = Math.max(1, Math.ceil((new Date(flow.expiresAt).getTime() - Date.now()) / 1000))
  await redis.set(key(id), JSON.stringify(updated), { ex: remainingTtl })
}
