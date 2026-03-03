import type { InferSelectModel } from 'drizzle-orm'
import type { services } from './db/schema'

type ServiceRow = InferSelectModel<typeof services>

export function wantsJson(accept: string | undefined) {
  if (!accept) return false
  return accept.includes('application/json')
}

export function buildUnauthDiscovery(svc: ServiceRow, baseUrl: string, flowId?: string) {
  const supported: string[] = svc.supportedAuthMethods
    ? JSON.parse(svc.supportedAuthMethods)
    : []

  const result: Record<string, unknown> = {
    service: svc.displayName ?? svc.service,
    canonical: svc.service,
  }

  if (svc.description) result.description = svc.description

  // Pick the first supported auth method and build an absolute URL with flow ID
  const flowParam = flowId ? `?flow_id=${flowId}` : ''
  for (const method of supported) {
    if (method === 'oauth') {
      result.auth_url = `${baseUrl}/auth/${svc.service}/oauth${flowParam}`
      break
    }
    if (method === 'api_key') {
      result.auth_url = `${baseUrl}/auth/${svc.service}/api-key${flowParam}`
      break
    }
  }

  if (flowId) {
    result.poll_url = `${baseUrl}/auth/status/${flowId}`
  }

  result.proxy = `${baseUrl}/${svc.service}`
  if (svc.preview) result.preview = JSON.parse(svc.preview)
  if (svc.docsUrl) result.docs_url = svc.docsUrl
  result.docs = `/${svc.service}/docs/`

  return result
}

export function buildAuthDiscovery(svc: ServiceRow, identity: string, baseUrl: string) {
  const result: Record<string, unknown> = {
    service: svc.displayName ?? svc.service,
    canonical: svc.service,
    authenticated_as: identity,
    proxy: `${baseUrl}/${svc.service}`,
  }

  if (svc.apiType) result.api_type = svc.apiType
  if (svc.docsUrl) result.docs_url = svc.docsUrl
  result.docs = `/${svc.service}/docs/`

  return result
}
