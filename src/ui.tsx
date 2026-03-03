/** @jsxImportSource hono/jsx */
import type { InferSelectModel } from 'drizzle-orm'
import type { services } from './db/schema'

type ServiceRow = InferSelectModel<typeof services>

const STYLES = `
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, system-ui, sans-serif; background: #0a0a0a; color: #e5e5e5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .container { max-width: 480px; width: 100%; padding: 2rem; }
  h1 { font-size: 1.5rem; margin-bottom: 0.5rem; color: #fff; }
  .subtitle { color: #888; margin-bottom: 2rem; }
  .card { background: #171717; border: 1px solid #262626; border-radius: 12px; padding: 1.5rem; margin-bottom: 1rem; }
  .btn { display: inline-block; padding: 0.75rem 1.5rem; border-radius: 8px; text-decoration: none; font-weight: 500; cursor: pointer; border: none; font-size: 0.875rem; }
  .btn-primary { background: #fff; color: #000; }
  .btn-secondary { background: #262626; color: #e5e5e5; border: 1px solid #404040; }
  .btn:hover { opacity: 0.9; }
  input[type="text"], input[type="password"] { width: 100%; padding: 0.75rem; border-radius: 8px; border: 1px solid #404040; background: #0a0a0a; color: #e5e5e5; font-size: 0.875rem; margin-bottom: 1rem; }
  input:focus { outline: none; border-color: #888; }
  .token-box { background: #0a0a0a; border: 1px solid #404040; border-radius: 8px; padding: 1rem; word-break: break-all; font-family: monospace; font-size: 0.8rem; margin: 1rem 0; color: #22c55e; }
  .meta { color: #666; font-size: 0.8rem; margin-top: 0.5rem; }
  .badge { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; background: #1a3a1a; color: #22c55e; }
  .error { color: #ef4444; }
  .auth-options { display: flex; flex-direction: column; gap: 0.75rem; }
  label { display: block; margin-bottom: 0.25rem; font-size: 0.875rem; color: #aaa; }
`

function Layout({ children }: { children: any }) {
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Warden</title>
        <style>{STYLES}</style>
      </head>
      <body>
        <div class="container">{children}</div>
      </body>
    </html>
  )
}

export function ServiceLandingPage({
  service,
  identity,
}: {
  service: ServiceRow
  identity?: string
}) {
  const supported: string[] = service.supportedAuthMethods
    ? JSON.parse(service.supportedAuthMethods)
    : []

  return (
    <Layout>
      <h1>{service.displayName ?? service.service}</h1>
      {service.description && <p class="subtitle">{service.description}</p>}

      {identity ? (
        <div class="card">
          <p>
            Authenticated as <span class="badge">{identity}</span>
          </p>
          <p class="meta">Service: {service.service}</p>
          {service.docsUrl && (
            <p class="meta">
              <a href={service.docsUrl} style="color: #888">
                API Documentation
              </a>
            </p>
          )}
        </div>
      ) : (
        <div class="card">
          <p style="margin-bottom: 1rem">Connect to start using this API through Warden.</p>
          <div class="auth-options">
            {supported.includes('oauth') && (
              <a href={`/auth/${service.service}/oauth`} class="btn btn-primary">
                Connect with OAuth
              </a>
            )}
            {supported.includes('api_key') && (
              <a href={`/auth/${service.service}/api-key`} class="btn btn-secondary">
                Enter API Key
              </a>
            )}
          </div>
          {service.docsUrl && (
            <p class="meta" style="margin-top: 1rem">
              <a href={service.docsUrl} style="color: #888">
                API Documentation
              </a>
            </p>
          )}
        </div>
      )}
    </Layout>
  )
}

export function ApiKeyFormPage({
  service,
  flowId,
}: {
  service: ServiceRow
  flowId: string
}) {
  return (
    <Layout>
      <h1>{service.displayName ?? service.service}</h1>
      <p class="subtitle">Enter your API key to connect.</p>

      <div class="card">
        <form method="post" action={`/auth/${service.service}/api-key`}>
          <input type="hidden" name="flow_id" value={flowId} />
          <label for="api_key">API Key</label>
          <input
            type="password"
            id="api_key"
            name="api_key"
            placeholder="Enter your API key"
            required
          />
          <button type="submit" class="btn btn-primary" style="width: 100%">
            Connect
          </button>
        </form>
        {service.docsUrl && (
          <p class="meta" style="margin-top: 1rem">
            Need a key?{' '}
            <a href={service.docsUrl} style="color: #888">
              Get one from {service.displayName ?? service.service}
            </a>
          </p>
        )}
      </div>
    </Layout>
  )
}

export function SuccessPage({
  token,
  service,
}: {
  token: string
  service: ServiceRow
}) {
  return (
    <Layout>
      <h1>Connected</h1>
      <p class="subtitle">
        You're connected to {service.displayName ?? service.service}.
      </p>

      <div class="card">
        <p>Your Warden Token</p>
        <div class="token-box" id="token">
          {token}
        </div>
        <button
          type="button"
          class="btn btn-primary"
          style="width: 100%"
          onclick="navigator.clipboard.writeText(document.getElementById('token').textContent.trim())"
        >
          Copy Token
        </button>
        <p class="meta" style="margin-top: 0.75rem">
          Give this token to your agent. It can be revoked at any time.
        </p>
      </div>
    </Layout>
  )
}

export function ErrorPage({ message }: { message: string }) {
  return (
    <Layout>
      <h1>Error</h1>
      <div class="card">
        <p class="error">{message}</p>
      </div>
    </Layout>
  )
}
