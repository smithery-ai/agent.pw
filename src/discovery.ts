import type { InferSelectModel } from 'drizzle-orm'
import type { services } from './db/schema'

type ServiceRow = InferSelectModel<typeof services>

export function wantsJson(accept: string | undefined) {
  if (!accept) return false
  return accept.includes('application/json')
}

export function buildUnauthDiscovery(svc: ServiceRow) {
  const authOptions: { type: string; setup_url: string }[] = []

  const supported: string[] = svc.supportedAuthMethods
    ? JSON.parse(svc.supportedAuthMethods)
    : []

  for (const method of supported) {
    if (method === 'oauth') {
      authOptions.push({ type: 'oauth', setup_url: `/auth/${svc.service}/oauth` })
    } else if (method === 'api_key') {
      authOptions.push({ type: 'api_key', setup_url: `/auth/${svc.service}/api-key` })
    }
  }

  const result: Record<string, unknown> = {
    service: svc.displayName ?? svc.service,
    canonical: svc.service,
  }

  if (svc.description) result.description = svc.description
  if (authOptions.length > 0) result.auth_options = authOptions
  if (svc.preview) result.preview = JSON.parse(svc.preview)
  if (svc.docsUrl) result.docs_url = svc.docsUrl
  result.docs = `/${svc.service}/docs/`

  return result
}

export function buildAuthDiscovery(svc: ServiceRow, identity: string) {
  const result: Record<string, unknown> = {
    service: svc.displayName ?? svc.service,
    canonical: svc.service,
    authenticated_as: identity,
  }

  if (svc.apiType) result.api_type = svc.apiType
  if (svc.baseUrl) result.base_url = `/${svc.service}`
  if (svc.docsUrl) result.docs_url = svc.docsUrl
  result.docs = `/${svc.service}/docs/`

  return result
}
