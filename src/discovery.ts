import type { InferSelectModel } from 'drizzle-orm'
import type { services } from './db/schema'
import { parseAuthSchemes, getOAuthScheme } from './auth-schemes'

type ServiceRow = InferSelectModel<typeof services>

export function wantsJson(accept: string | undefined) {
  if (!accept) return false
  if (accept.includes('application/json')) return true
  // curl sends */* by default; browsers always include text/html
  if (accept.includes('*/*') && !accept.includes('text/html')) return true
  return false
}

export function buildUnauthDiscovery(svc: ServiceRow, baseUrl: string, flowId?: string) {
  const schemes = parseAuthSchemes(svc.authSchemes)
  const oauthScheme = getOAuthScheme(schemes)

  const result: Record<string, unknown> = {
    service: svc.displayName ?? svc.service,
    canonical: svc.service,
  }

  if (svc.description) result.description = svc.description

  // Only include auth_url and auth_methods when the service has known auth schemes.
  // Services still being discovered have empty schemes — agents should wait.
  if (schemes.length > 0) {
    const flowParam = flowId ? `?flow_id=${flowId}` : ''
    result.auth_url = `${baseUrl}/auth/${svc.service}${flowParam}`

    const authMethods: { type: string; mode?: string }[] = []
    if (oauthScheme && svc.oauthClientId) {
      authMethods.push({ type: 'oauth', mode: 'managed' })
    }
    if (oauthScheme) {
      authMethods.push({ type: 'oauth', mode: 'byo' })
    }
    authMethods.push({ type: 'api_key' })
    result.auth_methods = authMethods

    if (flowId) {
      result.poll_url = `${baseUrl}/auth/status/${flowId}`
    }
  }

  result.proxy = `${baseUrl}/${svc.service}`
  if (svc.preview) result.preview = JSON.parse(svc.preview)
  if (svc.docsUrl) result.docs_url = svc.docsUrl
  result.sitemap = `/${svc.service}/sitemap/`

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
      sitemap: {
        method: 'GET',
        path: '/{hostname}/sitemap/',
        description:
          'API sitemap with resources, operations, and links to upstream docs.',
      },
      hooks_register_via_proxy: {
        method: 'POST',
        path: '/{hostname}/{webhook_endpoint}',
        description:
          'Create a webhook through the proxy with Warden-Callback header. Use $WARDEN_HOOK_URL and $WARDEN_HOOK_SECRET placeholders in the body — Warden replaces them with generated values, stores the webhook secret, and registers the forwarding target. One call.',
        headers: {
          Authorization: 'Bearer <warden_token>',
          'Warden-Callback': '<your_callback_url>',
        },
      },
      hooks_registrations: {
        method: 'GET',
        path: '/hooks/registrations',
        description: 'List your webhook registrations.',
        headers: { Authorization: 'Bearer <warden_token>' },
      },
      hooks_ingestion: {
        method: 'POST',
        path: '/hooks/{hostname}/{id}',
        description:
          'Webhook ingestion endpoint. Upstream services POST here. Not called by agents directly.',
      },
      hooks_verification: {
        method: 'GET',
        path: '/.well-known/jwks.json',
        description:
          'Ed25519 public key (JWK) for verifying Warden-Signature on forwarded events.',
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
    example_webhook_flow: {
      description: 'Subscribe to GitHub push events via webhook',
      steps: [
        {
          request: `POST ${baseUrl}/api.github.com/repos/{owner}/{repo}/hooks`,
          headers: {
            Authorization: 'Bearer <token>',
            'Content-Type': 'application/json',
            'Warden-Callback': 'https://your-agent.example.com/on-push',
          },
          body: JSON.stringify({
            events: ['push'],
            config: {
              url: '$WARDEN_HOOK_URL',
              secret: '$WARDEN_HOOK_SECRET',
              content_type: 'json',
            },
          }),
          note: 'Warden replaces placeholders, stores the secret, and registers forwarding. Returns the GitHub response with a Warden-Registration-Id header.',
        },
        {
          event: 'GitHub sends push event to Warden',
          note: 'Warden verifies the upstream signature, wraps the payload in a WardenWebhookEnvelope, signs it with Ed25519, and forwards to your callback.',
        },
        {
          verification: `GET ${baseUrl}/.well-known/jwks.json`,
          note: 'Fetch the Ed25519 public key to verify the Warden-Signature header on forwarded events.',
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
| \`GET\` | \`/{hostname}/sitemap/\` | API sitemap with resources and operations |
| \`POST\` | \`/{hostname}/{webhook_endpoint}\` | Create webhook with \`Warden-Callback\` header |
| \`GET\` | \`/hooks/registrations\` | List webhook registrations |
| \`GET\` | \`/.well-known/jwks.json\` | Ed25519 public key for verifying forwarded events |

## Webhooks (Events)

Warden normalizes webhook verification — register once, receive events
with a consistent \`Warden-Signature\` header signed by Warden's Ed25519 key.

1. **Create a webhook** through the proxy with the \`Warden-Callback\` header:
   \`\`\`
   curl -X POST ${baseUrl}/{hostname}/{webhook_endpoint} \\
     -H "Authorization: Bearer <token>" \\
     -H "Warden-Callback: https://your-agent.example.com/callback" \\
     -H "Content-Type: application/json" \\
     -d '{"url": "$WARDEN_HOOK_URL", "secret": "$WARDEN_HOOK_SECRET"}'
   \`\`\`
   Warden replaces \`$WARDEN_HOOK_URL\` and \`$WARDEN_HOOK_SECRET\` with
   generated values, stores the secret, and registers the forwarding.

2. **Receive events** at your callback URL. Each event is wrapped in a
   \`WardenWebhookEnvelope\` and signed with Warden's Ed25519 key.

3. **Verify the signature** using the public key from
   \`${baseUrl}/.well-known/jwks.json\` and the \`Warden-Signature\` header.

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
  result.sitemap = `/${svc.service}/sitemap/`

  return result
}
