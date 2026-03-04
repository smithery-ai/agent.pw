/** @jsxImportSource hono/jsx */
import type { InferSelectModel } from 'drizzle-orm'
import type { services } from './db/schema'

type ServiceRow = InferSelectModel<typeof services>

const STYLES = `
  :root {
    --background: #09090b;
    --foreground: #fafafa;
    --card: #111113;
    --card-foreground: #fafafa;
    --muted: #27272a;
    --muted-foreground: #a1a1aa;
    --border: #1e1e21;
    --input: #27272a;
    --ring: #d4d4d8;
    --primary: #fafafa;
    --primary-foreground: #09090b;
    --secondary: #27272a;
    --secondary-foreground: #fafafa;
    --accent: #27272a;
    --destructive: #ef4444;
    --success: #4ade80;
    --radius: 0.5rem;
  }
  *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', sans-serif;
    background: var(--background); color: var(--foreground);
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale;
  }
  .container { max-width: 640px; width: 100%; padding: 2rem; }

  .service-header { text-align: center; margin-bottom: 1.5rem; }
  .service-icon {
    width: 56px; height: 56px; border-radius: 14px;
    background: var(--card); border: 1px solid var(--border);
    display: inline-flex; align-items: center; justify-content: center;
    margin-bottom: 0.875rem; font-size: 1.25rem; color: var(--muted-foreground);
    box-shadow: 0 1px 2px rgba(0,0,0,0.3);
  }
  .service-name {
    font-size: 1.125rem; font-weight: 600; color: var(--foreground);
    letter-spacing: -0.01em;
  }
  .service-host {
    font-size: 0.75rem; color: #52525b; margin-top: 0.25rem;
    font-family: 'SF Mono', SFMono-Regular, ui-monospace, monospace;
  }
  .subtitle { color: #71717a; font-size: 0.8125rem; margin-top: 0.375rem; line-height: 1.5; }

  .card {
    background: var(--card); border: 1px solid var(--border); border-radius: 12px;
    padding: 1.25rem; box-shadow: 0 1px 3px rgba(0,0,0,0.2), 0 0 0 1px rgba(255,255,255,0.03);
  }

  .btn {
    display: inline-flex; align-items: center; justify-content: center;
    height: 36px; padding: 0 1rem; border-radius: var(--radius); text-decoration: none;
    font-weight: 500; cursor: pointer; border: none; font-size: 0.8125rem;
    transition: background 0.15s ease, opacity 0.15s ease, box-shadow 0.15s ease;
    letter-spacing: -0.01em; line-height: 1;
  }
  .btn:active { transform: scale(0.98); }
  .btn-primary {
    background: var(--primary); color: var(--primary-foreground);
    box-shadow: 0 1px 2px rgba(0,0,0,0.2);
  }
  .btn-primary:hover { background: #e4e4e7; }
  .btn-secondary {
    background: var(--secondary); color: var(--secondary-foreground);
    border: 1px solid #3f3f46;
  }
  .btn-secondary:hover { background: #3f3f46; }

  label, .card-label {
    display: block; margin-bottom: 0.375rem;
    font-size: 0.8125rem; color: var(--muted-foreground); font-weight: 500;
  }
  input[type="text"], input[type="password"] {
    width: 100%; height: 36px; padding: 0 0.75rem; border-radius: var(--radius);
    border: 1px solid var(--border); background: var(--background); color: var(--foreground);
    font-size: 0.8125rem;
    font-family: 'SF Mono', SFMono-Regular, ui-monospace, monospace;
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
  }
  input:focus {
    outline: none; border-color: #3f3f46;
    box-shadow: 0 0 0 3px rgba(212,212,216,0.08);
  }
  input::placeholder {
    color: #3f3f46;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', sans-serif;
  }

  .form-group { margin-bottom: 0.75rem; }

  .token-box {
    background: var(--background); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 0.75rem; word-break: break-all;
    font-family: 'SF Mono', SFMono-Regular, ui-monospace, monospace;
    font-size: 0.75rem; margin: 0.75rem 0; color: var(--success); line-height: 1.6;
  }
  .meta {
    color: #52525b; font-size: 0.75rem; margin-top: 0.75rem; line-height: 1.5;
  }
  .meta a {
    color: #71717a; text-decoration: underline;
    text-underline-offset: 2px; text-decoration-color: #3f3f46;
    transition: color 0.15s ease;
  }
  .meta a:hover { color: var(--muted-foreground); text-decoration-color: #71717a; }

  .badge {
    display: inline-block; padding: 0.125rem 0.4rem; border-radius: 4px;
    font-size: 0.75rem; font-weight: 500; background: #052e16; color: var(--success);
    font-family: 'SF Mono', SFMono-Regular, ui-monospace, monospace;
  }
  .error { color: var(--destructive); font-size: 0.8125rem; }
  .auth-options { display: flex; flex-direction: column; gap: 0.5rem; }
  .tab-list {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 0.5rem;
    margin-bottom: 1rem;
  }
  .tab-radio {
    position: absolute;
    opacity: 0;
    pointer-events: none;
  }
  .tab-label {
    display: inline-flex; align-items: center; justify-content: center;
    text-align: center; min-height: 36px; border-radius: var(--radius);
    border: 1px solid #3f3f46; background: #18181b; color: #a1a1aa;
    font-size: 0.75rem; font-weight: 500; cursor: pointer; padding: 0 0.5rem;
    transition: border-color 0.15s ease, color 0.15s ease, background 0.15s ease;
  }
  .tab-radio:checked + .tab-label {
    border-color: #71717a; background: #27272a; color: var(--foreground);
  }
  .tab-panel {
    display: none;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: #0c0c0f;
    padding: 1rem;
  }
  #tab-managed:checked ~ .tab-panels .panel-managed { display: block; }
  #tab-byo:checked ~ .tab-panels .panel-byo { display: block; }
  #tab-api:checked ~ .tab-panels .panel-api { display: block; }
  .helper {
    color: #71717a;
    font-size: 0.75rem;
    line-height: 1.5;
    margin-top: 0.625rem;
  }
  .helper code {
    color: var(--foreground);
    background: var(--muted);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.1rem 0.25rem;
    font-size: 0.6875rem;
    word-break: break-all;
  }
  .divider { border: none; border-top: 1px solid var(--border); margin: 1rem 0; }

  .status-bar {
    display: flex; align-items: center; gap: 0.5rem;
    padding: 0.625rem 0.75rem; border-radius: var(--radius);
    background: var(--card); border: 1px solid var(--border);
    font-size: 0.75rem; color: #71717a; margin-top: 0.75rem;
  }
  .status-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
  .status-dot.active { background: #facc15; animation: pulse 1.5s ease-in-out infinite; }
  .status-dot.done { background: var(--success); }
  .status-dot.idle { background: #52525b; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

  .warden-badge {
    text-align: center; margin-top: 1.5rem;
    font-size: 0.6875rem; color: #27272a; letter-spacing: 0.01em;
  }
  .warden-badge a {
    color: #3f3f46; text-decoration: none;
    transition: color 0.15s ease;
  }
  .warden-badge a:hover { color: #52525b; }

  @media (max-width: 640px) {
    body { align-items: flex-start; padding: 1rem 0; }
    .container { padding: 1rem; }
    .tab-list { grid-template-columns: 1fr; }
  }
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

export function WardenLandingPage({ services = [] }: { services?: ServiceRow[] } = {}) {
  return (
    <Layout title="Warden — Authenticated API Proxy for Agents">
      <div class="service-header">
        <div class="service-icon" style="font-weight: 700; font-size: 1.125rem; color: var(--foreground)">W</div>
        <div class="service-name">Warden</div>
        <p class="subtitle">Authenticated API proxy for agents</p>
      </div>

      {services.length > 0 && (
        <div class="card" style="margin-bottom: 0.75rem">
          <span class="card-label">Services</span>
          <div style="margin-top: 0.5rem; display: flex; flex-direction: column; gap: 0.375rem">
            {services.map(s => (
              <a href={`/${s.service}`} style="display: flex; align-items: center; gap: 0.5rem; text-decoration: none; padding: 0.375rem 0.5rem; border-radius: var(--radius); transition: background 0.15s ease; font-size: 0.8125rem"
                onmouseover="this.style.background='var(--muted)'" onmouseout="this.style.background='transparent'">
                <span style="width: 28px; height: 28px; border-radius: 7px; background: var(--muted); border: 1px solid var(--border); display: inline-flex; align-items: center; justify-content: center; font-size: 0.75rem; color: var(--muted-foreground); flex-shrink: 0">
                  {(s.displayName ?? s.service).charAt(0).toUpperCase()}
                </span>
                <span style="color: var(--foreground); font-weight: 500">{s.displayName ?? s.service}</span>
                <span style="color: #3f3f46; font-family: 'SF Mono', monospace; font-size: 0.6875rem; margin-left: auto">{s.service}</span>
              </a>
            ))}
          </div>
        </div>
      )}

      <div class="card" style="margin-bottom: 0.75rem">
        <span class="card-label">Quick Start</span>
        <ol style="list-style: none; counter-reset: step; padding: 0; margin: 0.5rem 0 0 0; display: flex; flex-direction: column; gap: 0.625rem">
          <li style="display: flex; gap: 0.5rem; font-size: 0.8125rem; color: var(--muted-foreground); line-height: 1.5">
            <span style="color: var(--foreground); font-weight: 600; flex-shrink: 0">1.</span>
            <span>Discover a service by requesting <code style="color: var(--foreground); font-family: 'SF Mono', monospace; font-size: 0.75rem; background: var(--muted); padding: 0.1rem 0.3rem; border-radius: 3px">GET /&#123;hostname&#125;</code> with <code style="color: var(--foreground); font-family: 'SF Mono', monospace; font-size: 0.75rem; background: var(--muted); padding: 0.1rem 0.3rem; border-radius: 3px">Accept: application/json</code></span>
          </li>
          <li style="display: flex; gap: 0.5rem; font-size: 0.8125rem; color: var(--muted-foreground); line-height: 1.5">
            <span style="color: var(--foreground); font-weight: 600; flex-shrink: 0">2.</span>
            <span>Present the <code style="color: var(--foreground); font-family: 'SF Mono', monospace; font-size: 0.75rem; background: var(--muted); padding: 0.1rem 0.3rem; border-radius: 3px">auth_url</code> to the user and poll <code style="color: var(--foreground); font-family: 'SF Mono', monospace; font-size: 0.75rem; background: var(--muted); padding: 0.1rem 0.3rem; border-radius: 3px">poll_url</code> until completed</span>
          </li>
          <li style="display: flex; gap: 0.5rem; font-size: 0.8125rem; color: var(--muted-foreground); line-height: 1.5">
            <span style="color: var(--foreground); font-weight: 600; flex-shrink: 0">3.</span>
            <span>Proxy requests through <code style="color: var(--foreground); font-family: 'SF Mono', monospace; font-size: 0.75rem; background: var(--muted); padding: 0.1rem 0.3rem; border-radius: 3px">/&#123;hostname&#125;/path</code> with <code style="color: var(--foreground); font-family: 'SF Mono', monospace; font-size: 0.75rem; background: var(--muted); padding: 0.1rem 0.3rem; border-radius: 3px">Authorization: Bearer &lt;token&gt;</code></span>
          </li>
        </ol>
      </div>

      <div class="card">
        <span class="card-label">Routes</span>
        <div style="margin-top: 0.5rem; display: flex; flex-direction: column; gap: 0.5rem">
          <div style="font-size: 0.8125rem">
            <code style="color: var(--success); font-family: 'SF Mono', monospace; font-size: 0.75rem">GET /&#123;hostname&#125;</code>
            <span style="color: var(--muted-foreground); margin-left: 0.375rem">Discovery + auth flow</span>
          </div>
          <div style="font-size: 0.8125rem">
            <code style="color: var(--success); font-family: 'SF Mono', monospace; font-size: 0.75rem">GET /auth/status/&#123;flow_id&#125;</code>
            <span style="color: var(--muted-foreground); margin-left: 0.375rem">Poll auth completion</span>
          </div>
          <div style="font-size: 0.8125rem">
            <code style="color: var(--success); font-family: 'SF Mono', monospace; font-size: 0.75rem">ANY /&#123;hostname&#125;/&#123;path&#125;</code>
            <span style="color: var(--muted-foreground); margin-left: 0.375rem">Authenticated proxy</span>
          </div>
          <div style="font-size: 0.8125rem">
            <code style="color: var(--success); font-family: 'SF Mono', monospace; font-size: 0.75rem">GET /&#123;hostname&#125;/docs/</code>
            <span style="color: var(--muted-foreground); margin-left: 0.375rem">Generated API docs</span>
          </div>
        </div>
      </div>
    </Layout>
  )
}

export function ServiceLandingPage({
  service,
  discoveryStatus,
  userCredentials,
}: {
  service: ServiceRow
  discoveryStatus?: Record<string, unknown>
  userCredentials?: { slug: string; updatedAt: Date }[]
}) {
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

      {userCredentials && userCredentials.length > 0 && (
        <div class="card" style="margin-bottom: 0.75rem">
          <span class="card-label">Your credentials</span>
          <div style="margin-top: 0.5rem; display: flex; flex-direction: column; gap: 0.375rem">
            {userCredentials.map(cr => {
              const ago = formatTimeAgo(cr.updatedAt)
              return (
                <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.8125rem; padding: 0.375rem 0.5rem; border-radius: var(--radius); background: var(--muted)">
                  <span style="color: var(--success); flex-shrink: 0">&#10003;</span>
                  <span style="color: var(--foreground)">
                    {cr.slug}
                  </span>
                  <span style="color: #52525b; font-size: 0.75rem; margin-left: auto">{ago}</span>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {userCredentials && userCredentials.length > 0 ? (
        <div class="card">
          <p>Connected</p>
          {service.docsUrl && (
            <p class="meta">
              <a href={service.docsUrl}>API Documentation</a>
            </p>
          )}
        </div>
      ) : (
        <div class="card">
          {service.description && (
            <p class="subtitle" style="margin-bottom: 0.75rem">{service.description}</p>
          )}
          <div class="auth-options">
            <a href={`/auth/${service.service}`} class="btn btn-primary" style="width: 100%">
              Authenticate
            </a>
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

export function AuthPage({
  service,
  flowId,
  callbackUrl,
}: {
  service: ServiceRow
  flowId: string
  callbackUrl: string
}) {
  const hasManagedOAuth = !!service.oauthClientId
  const hasByoOAuth = !!service.oauthAuthorizeUrl
  const defaultTab = hasManagedOAuth ? 'managed' : hasByoOAuth ? 'byo' : 'api'
  const name = service.displayName ?? service.service

  return (
    <Layout title={`Connect ${name} — Warden`}>
      <ServiceHeader service={service} />

      <div class="card">
        <div class="tab-list">
          {hasManagedOAuth && (
            <>
              <input
                class="tab-radio"
                id="tab-managed"
                type="radio"
                name="auth-tab"
                checked={defaultTab === 'managed'}
              />
              <label class="tab-label" for="tab-managed">OAuth</label>
            </>
          )}

          {hasByoOAuth && (
            <>
              <input
                class="tab-radio"
                id="tab-byo"
                type="radio"
                name="auth-tab"
                checked={defaultTab === 'byo'}
              />
              <label class="tab-label" for="tab-byo">Your OAuth App</label>
            </>
          )}

          <input
            class="tab-radio"
            id="tab-api"
            type="radio"
            name="auth-tab"
            checked={defaultTab === 'api'}
          />
          <label class="tab-label" for="tab-api">API Key</label>
        </div>

        <div class="tab-panels">
          {hasManagedOAuth && (
            <div class="tab-panel panel-managed">
              <a
                href={`/auth/${service.service}/oauth?flow_id=${flowId}&source=managed`}
                class="btn btn-primary"
                style="width: 100%"
              >
                Connect with OAuth
              </a>
              <p class="helper">
                Use Warden&apos;s pre-configured OAuth app for {name}.
              </p>
            </div>
          )}

          {hasByoOAuth && (
            <div class="tab-panel panel-byo">
              <form method="post" action={`/auth/${service.service}/oauth/byo`}>
                <input type="hidden" name="flow_id" value={flowId} />
                <div class="form-group">
                  <label for="client_id">Client ID</label>
                  <input
                    type="text"
                    id="client_id"
                    name="client_id"
                    placeholder="Your OAuth app client_id"
                    required
                    autocomplete="off"
                    spellcheck={false}
                  />
                </div>
                <div class="form-group">
                  <label for="client_secret">Client Secret</label>
                  <input
                    type="password"
                    id="client_secret"
                    name="client_secret"
                    placeholder="Your OAuth app client_secret"
                    autocomplete="off"
                    spellcheck={false}
                  />
                </div>
                <div class="form-group" style="margin-bottom: 0.875rem">
                  <label for="scopes">Scopes (optional override)</label>
                  <input
                    type="text"
                    id="scopes"
                    name="scopes"
                    placeholder={service.oauthScopes ?? 'repo read:user'}
                    autocomplete="off"
                    spellcheck={false}
                  />
                </div>
                <button type="submit" class="btn btn-primary" style="width: 100%">
                  Save and Connect
                </button>
              </form>
              <p class="helper">
                Register this redirect URI in your OAuth app: <code>{callbackUrl}</code>
              </p>
            </div>
          )}

          <div class="tab-panel panel-api">
            <form method="post" action={`/auth/${service.service}/api-key`}>
              <input type="hidden" name="flow_id" value={flowId} />
              <div class="form-group">
                <label for="api_key_inline">API Key</label>
                <input
                  type="password"
                  id="api_key_inline"
                  name="api_key"
                  placeholder={`Paste your ${name} API key`}
                  required
                  autocomplete="off"
                  spellcheck={false}
                />
              </div>
              <button type="submit" class="btn btn-secondary" style="width: 100%">
                Connect with API Key
              </button>
            </form>
            {service.docsUrl && (
              <p class="helper">
                Need a key?{' '}
                <a href={service.docsUrl} target="_blank" rel="noopener noreferrer">
                  Get one from {name}
                </a>
              </p>
            )}
          </div>
        </div>
      </div>
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
          <div class="form-group">
            <label for="api_key">API Key</label>
            <input
              type="password"
              id="api_key"
              name="api_key"
              placeholder={`Paste your ${name} API key`}
              required
              autocomplete="off"
              spellcheck={false}
            />
          </div>
          <button type="submit" class="btn btn-primary" style="width: 100%">
            Connect
          </button>
        </form>
        {service.docsUrl && (
          <p class="meta">
            Need a key?{' '}
            <a href={service.docsUrl} target="_blank" rel="noopener noreferrer">
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
        <span class="card-label">Your Warden token</span>
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
          This token works for all your connected services. Give it to your agent.
        </p>
      </div>
    </Layout>
  )
}

function formatTimeAgo(date: Date) {
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000)
  if (seconds < 60) return 'just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
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
