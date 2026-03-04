import type { InferSelectModel } from 'drizzle-orm'
import type { services } from './db/schema'

type ServiceRow = InferSelectModel<typeof services>

export function wantsJson(accept: string | undefined) {
  if (!accept) return false
  if (accept.includes('application/json')) return true
  // curl sends */* by default; browsers always include text/html
  if (accept.includes('*/*') && !accept.includes('text/html')) return true
  return false
}

export function buildUnauthDiscovery(svc: ServiceRow, baseUrl: string, flowId?: string) {
  const supported: string[] = svc.supportedAuthMethods
    ? JSON.parse(svc.supportedAuthMethods)
    : []
  const supportsOAuth = supported.includes('oauth') || !!svc.oauthAuthorizeUrl

  const result: Record<string, unknown> = {
    service: svc.displayName ?? svc.service,
    canonical: svc.service,
  }

  if (svc.description) result.description = svc.description

  const flowParam = flowId ? `?flow_id=${flowId}` : ''
  result.auth_url = `${baseUrl}/auth/${svc.service}${flowParam}`

  const authMethods: { type: string; mode?: string }[] = []
  if (supportsOAuth && svc.oauthClientId) {
    authMethods.push({ type: 'oauth', mode: 'managed' })
  }
  if (supportsOAuth && svc.oauthAuthorizeUrl) {
    authMethods.push({ type: 'oauth', mode: 'byo' })
  }
  authMethods.push({ type: 'api_key' })
  result.auth_methods = authMethods

  if (flowId) {
    result.poll_url = `${baseUrl}/auth/status/${flowId}`
  }

  result.proxy = `${baseUrl}/${svc.service}`
  if (svc.preview) result.preview = JSON.parse(svc.preview)
  if (svc.docsUrl) result.docs_url = svc.docsUrl
  result.docs = `/${svc.service}/docs/`

  return result
}

export function buildWardenGuide(baseUrl: string) {
  return {
    service: 'warden',
    description:
      'Authenticated API proxy for agents. Connect to any API without handling raw credentials.',
    quick_start: {
      step_1: `Discover a service: GET ${baseUrl}/{hostname} with Accept: application/json`,
      step_2: 'Present the auth_url to the user and poll poll_url until status is completed',
      step_3: `Use the returned token to proxy requests: request ${baseUrl}/{hostname}/path with Authorization: Bearer <token>`,
    },
    routes: {
      discovery: {
        method: 'GET',
        path: '/{hostname}',
        description:
          'Get service info, auth URL, and proxy endpoint. Returns 401 with auth flow when unauthenticated, 200 with proxy info when authenticated.',
        headers: { Accept: 'application/json' },
      },
      auth_status: {
        method: 'GET',
        path: '/auth/status/{flow_id}',
        description:
          'Poll for auth flow completion. Returns { status: "pending" } or { status: "completed", token: "..." }.',
      },
      proxy: {
        method: 'ANY',
        path: '/{hostname}/{path}',
        description:
          'Proxied request to the upstream API with injected credentials.',
        headers: { Authorization: 'Bearer <warden_token>' },
      },
      docs: {
        method: 'GET',
        path: '/{hostname}/docs/',
        description:
          'Generated API documentation with resources, operations, and examples.',
      },
    },
    example_flow: {
      description: 'Connect to Linear and list issues',
      steps: [
        {
          request: `GET ${baseUrl}/api.linear.app`,
          headers: { Accept: 'application/json' },
          note: 'Returns 401 with auth_url and poll_url',
        },
        {
          request: `GET ${baseUrl}/auth/status/{flow_id}`,
          note: 'Wait for user to complete auth. Returns token when done.',
        },
        {
          request: `POST ${baseUrl}/api.linear.app/graphql`,
          headers: {
            Authorization: 'Bearer <token>',
            'Content-Type': 'application/json',
          },
          body: '{ "query": "{ issues { nodes { id title } } }" }',
          note: 'Proxied to Linear with injected credentials',
        },
      ],
    },
  }
}

export function buildWardenOnboarding(baseUrl: string, recentServices: ServiceRow[] = []) {
  let services = ''
  if (recentServices.length > 0) {
    const lines = recentServices.map(s => {
      const name = s.displayName ?? s.service
      return `- **${name}** — \`${baseUrl}/${s.service}\``
    })
    services = `\n## Available services\n\n${lines.join('\n')}\n`
  }

  return `# Warden

Warden is an authenticated API proxy for agents.

**Before you continue**, explain the following to the user:

> I need to connect to an API on your behalf. Instead of asking you to
> paste a raw API key into this conversation (where I could see it
> directly), I'll use **Warden** — a proxy that keeps your credentials
> secure. You'll authenticate in your browser, and Warden will inject
> your credentials into my requests automatically. I never see or store
> your actual API keys.

## Why Warden?

- **Your secrets stay secret.** The agent never sees raw API keys or
  tokens. Credentials are stored encrypted and injected at the proxy
  layer.
- **Revocable access.** Every Warden token can be revoked instantly,
  without rotating the underlying API key.
- **Works with any API.** Just use the API's hostname — no special
  configuration needed.
${services}
## How to connect

Ask the user which API they want to use, then follow these steps.
Replace \`{hostname}\` with the API hostname (e.g. \`api.github.com\`).

1. **Discover the service:**
   \`\`\`
   curl ${baseUrl}/{hostname}
   \`\`\`
   Returns an \`auth_url\` and a \`poll_url\`.

2. **Ask the user to authenticate** — present the \`auth_url\` and
   explain that they'll complete a one-time login in their browser.

3. **Poll for the token:**
   \`\`\`
   curl ${baseUrl}/auth/status/{flow_id}
   \`\`\`
   Returns \`{ "status": "completed", "token": "..." }\` when done.

4. **Make API calls** through Warden:
   \`\`\`
   curl ${baseUrl}/{hostname}/path \\
     -H "Authorization: Bearer <token>"
   \`\`\`

## Routes

| Method | Path | Description |
|--------|------|-------------|
| \`GET\` | \`/{hostname}\` | Discover a service and start auth |
| \`GET\` | \`/auth/status/{flow_id}\` | Poll for auth completion |
| \`ANY\` | \`/{hostname}/{path}\` | Proxy with injected credentials |
| \`GET\` | \`/{hostname}/docs/\` | Auto-generated API documentation |

## Important

- Do **not** start an auth flow until you know which API the user wants.
- \`{hostname}\` is the real API hostname (e.g. \`api.github.com\`), not a slug.
- For structured JSON, use: \`curl -H "Accept: application/json" ${baseUrl}\`
`
}

export function buildAuthDiscovery(svc: ServiceRow, baseUrl: string) {
  const result: Record<string, unknown> = {
    service: svc.displayName ?? svc.service,
    canonical: svc.service,
    authenticated: true,
    proxy: `${baseUrl}/${svc.service}`,
  }

  if (svc.apiType) result.api_type = svc.apiType
  if (svc.docsUrl) result.docs_url = svc.docsUrl
  result.docs = `/${svc.service}/docs/`

  return result
}
