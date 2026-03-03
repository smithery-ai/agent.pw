/** @jsxImportSource hono/jsx */
import type { InferSelectModel } from 'drizzle-orm'
import type { services } from './db/schema'

type ServiceRow = InferSelectModel<typeof services>

const STYLES = `
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, system-ui, 'Segoe UI', sans-serif;
    background: #09090b; color: #fafafa;
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
  }
  .container { max-width: 420px; width: 100%; padding: 2rem; }
  .service-header { text-align: center; margin-bottom: 2rem; }
  .service-icon {
    width: 48px; height: 48px; border-radius: 12px;
    background: #18181b; border: 1px solid #27272a;
    display: inline-flex; align-items: center; justify-content: center;
    margin-bottom: 1rem; font-size: 1.25rem; color: #a1a1aa;
  }
  .service-name { font-size: 1.25rem; font-weight: 600; color: #fafafa; }
  .service-host { font-size: 0.8rem; color: #52525b; margin-top: 0.25rem; font-family: monospace; }
  .subtitle { color: #71717a; font-size: 0.875rem; margin-top: 0.5rem; }
  .card {
    background: #18181b; border: 1px solid #27272a; border-radius: 16px;
    padding: 1.5rem;
  }
  .btn {
    display: inline-flex; align-items: center; justify-content: center;
    padding: 0.625rem 1.25rem; border-radius: 10px; text-decoration: none;
    font-weight: 500; cursor: pointer; border: none; font-size: 0.875rem;
    transition: all 0.15s ease;
  }
  .btn-primary { background: #fafafa; color: #09090b; }
  .btn-primary:hover { background: #e4e4e7; }
  .btn-secondary { background: #27272a; color: #fafafa; border: 1px solid #3f3f46; }
  .btn-secondary:hover { background: #3f3f46; }
  input[type="text"], input[type="password"] {
    width: 100%; padding: 0.625rem 0.75rem; border-radius: 10px;
    border: 1px solid #3f3f46; background: #09090b; color: #fafafa;
    font-size: 0.875rem; font-family: monospace;
    transition: border-color 0.15s ease;
  }
  input:focus { outline: none; border-color: #71717a; }
  input::placeholder { color: #52525b; font-family: -apple-system, system-ui, sans-serif; }
  .token-box {
    background: #09090b; border: 1px solid #27272a; border-radius: 10px;
    padding: 1rem; word-break: break-all; font-family: monospace;
    font-size: 0.8rem; margin: 1rem 0; color: #4ade80; line-height: 1.5;
  }
  .meta { color: #52525b; font-size: 0.8rem; margin-top: 0.75rem; }
  .meta a { color: #71717a; text-decoration: underline; text-underline-offset: 2px; }
  .meta a:hover { color: #a1a1aa; }
  .badge {
    display: inline-block; padding: 0.2rem 0.5rem; border-radius: 6px;
    font-size: 0.8rem; font-weight: 500; background: #052e16; color: #4ade80;
    font-family: monospace;
  }
  .error { color: #f87171; }
  .auth-options { display: flex; flex-direction: column; gap: 0.75rem; }
  label { display: block; margin-bottom: 0.5rem; font-size: 0.8rem; color: #a1a1aa; font-weight: 500; }
  .divider { border: none; border-top: 1px solid #27272a; margin: 1rem 0; }
  .status-bar {
    display: flex; align-items: center; gap: 0.5rem;
    padding: 0.75rem 1rem; border-radius: 10px;
    background: #09090b; border: 1px solid #27272a;
    font-size: 0.8rem; color: #71717a; margin-top: 1rem;
  }
  .status-dot {
    width: 6px; height: 6px; border-radius: 50%;
    flex-shrink: 0;
  }
  .status-dot.active { background: #facc15; animation: pulse 1.5s ease-in-out infinite; }
  .status-dot.done { background: #4ade80; }
  .status-dot.idle { background: #52525b; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
  .warden-badge {
    text-align: center; margin-top: 2rem; font-size: 0.75rem; color: #3f3f46;
  }
  .warden-badge a { color: #52525b; text-decoration: none; }
`

function Layout({ children, title }: { children: any; title?: string }) {
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{title ?? 'Warden'}</title>
        <style>{STYLES}</style>
      </head>
      <body>
        <div class="container">
          {children}
          <div class="warden-badge">
            Secured by <a href="https://warden.run">Warden</a>
          </div>
        </div>
      </body>
    </html>
  )
}

function ServiceHeader({ service }: { service: ServiceRow }) {
  const name = service.displayName ?? service.service
  const initial = name.charAt(0).toUpperCase()
  return (
    <div class="service-header">
      <div class="service-icon">{initial}</div>
      <div class="service-name">{name}</div>
      <div class="service-host">{service.service}</div>
    </div>
  )
}

export function ServiceLandingPage({
  service,
  identity,
  discoveryStatus,
}: {
  service: ServiceRow
  identity?: string
  discoveryStatus?: Record<string, unknown>
}) {
  const supported: string[] = service.supportedAuthMethods
    ? JSON.parse(service.supportedAuthMethods)
    : []

  const pipelineState = (discoveryStatus?.pipeline_state as string) ?? 'idle'
  const isActive = pipelineState === 'probing' || pipelineState === 'parsing' || pipelineState === 'enriching'
  const coverage = discoveryStatus?.coverage as { total_resources?: number; enriched_resources?: number } | undefined
  const totalPages = (discoveryStatus?.total_pages as number) ?? 0

  function statusLabel() {
    if (isActive) return `Discovering API (${pipelineState}...)`
    if (coverage && coverage.total_resources) return `${coverage.total_resources} resources discovered`
    if (totalPages > 0) return `${totalPages} doc pages`
    return 'No documentation yet'
  }

  return (
    <Layout title={`${service.displayName ?? service.service} — Warden`}>
      <ServiceHeader service={service} />

      {identity ? (
        <div class="card">
          <p>
            Authenticated as <span class="badge">{identity}</span>
          </p>
          {service.docsUrl && (
            <p class="meta">
              <a href={service.docsUrl}>API Documentation</a>
            </p>
          )}
        </div>
      ) : (
        <div class="card">
          {service.description && (
            <p class="subtitle" style="margin-bottom: 1rem">{service.description}</p>
          )}
          <div class="auth-options">
            {supported.includes('oauth') && (
              <a href={`/auth/${service.service}/oauth`} class="btn btn-primary" style="width: 100%">
                Connect with OAuth
              </a>
            )}
            {supported.includes('api_key') && (
              <a href={`/auth/${service.service}/api-key`} class="btn btn-secondary" style="width: 100%">
                Enter API Key
              </a>
            )}
          </div>
          {service.docsUrl && (
            <p class="meta">
              <a href={service.docsUrl}>API Documentation</a>
            </p>
          )}
        </div>
      )}

      {discoveryStatus && (
        <div class="status-bar">
          <span class={`status-dot ${isActive ? 'active' : coverage?.total_resources ? 'done' : 'idle'}`} />
          <span>{statusLabel()}</span>
          {!isActive && coverage?.total_resources ? (
            <a href={`/${service.service}/docs/`} style="margin-left: auto; color: #71717a; text-decoration: underline; text-underline-offset: 2px; font-size: 0.8rem">
              View docs
            </a>
          ) : null}
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
  const name = service.displayName ?? service.service
  return (
    <Layout title={`Connect ${name} — Warden`}>
      <ServiceHeader service={service} />

      <div class="card">
        <form method="post" action={`/auth/${service.service}/api-key`}>
          <input type="hidden" name="flow_id" value={flowId} />
          <label for="api_key">API Key</label>
          <input
            type="password"
            id="api_key"
            name="api_key"
            placeholder={`Paste your ${name} API key`}
            required
          />
          <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 0.5rem">
            Connect
          </button>
        </form>
        {service.docsUrl && (
          <p class="meta">
            Need a key?{' '}
            <a href={service.docsUrl}>
              Get one from {name}
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
  const name = service.displayName ?? service.service
  return (
    <Layout title={`Connected to ${name} — Warden`}>
      <ServiceHeader service={service} />

      <div class="card">
        <p style="font-size: 0.875rem; color: #a1a1aa; margin-bottom: 0.5rem">Your Warden token</p>
        <div class="token-box" id="token">
          {token}
        </div>
        <button
          type="button"
          class="btn btn-primary"
          style="width: 100%"
          onclick="navigator.clipboard.writeText(document.getElementById('token').textContent.trim()).then(()=>{this.textContent='Copied!';setTimeout(()=>{this.textContent='Copy Token'},2000)})"
        >
          Copy Token
        </button>
        <p class="meta">
          Give this token to your agent. It can be revoked at any time.
        </p>
      </div>
    </Layout>
  )
}

export function ErrorPage({ message }: { message: string }) {
  return (
    <Layout title="Error — Warden">
      <div class="service-header">
        <div class="service-icon" style="border-color: #7f1d1d; background: #18181b">!</div>
        <div class="service-name">Something went wrong</div>
      </div>
      <div class="card">
        <p class="error">{message}</p>
      </div>
    </Layout>
  )
}
