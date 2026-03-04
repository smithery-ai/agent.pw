/** @jsxImportSource hono/jsx */
import type { InferSelectModel } from 'drizzle-orm'
import type { services } from './db/schema'

type ServiceRow = InferSelectModel<typeof services>
type ServiceWithPopularity = ServiceRow & { credentialCount?: number }

const STYLES = `
  :root {
    --smithery-white: #ffffff;
    --smithery-offwhite: #efead6;
    --smithery-offblack: #232323;
    --smithery-yellow: #ffdc4a;
    --smithery-orange: #ff5601;
    --smithery-maroon: #7b1707;

    --paper: var(--smithery-offwhite);
    --ink: var(--smithery-offblack);
    --muted: #5a5750;
    --line: rgba(35, 35, 35, 0.16);
    --card: rgba(255, 255, 255, 0.78);
    --card-strong: rgba(255, 255, 255, 0.94);
    --radius: 16px;

    --font-sans: 'GT Pantheon Micro', 'Iowan Old Style', 'Palatino Linotype', 'Book Antiqua', Georgia, serif;
    --font-mono: ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace;
  }

  *, *::before, *::after { box-sizing: border-box; }

  body {
    margin: 0;
    min-height: 100vh;
    color: var(--ink);
    background: radial-gradient(1200px 520px at 92% -10%, rgba(255, 86, 1, 0.15), transparent 64%),
      radial-gradient(900px 460px at -8% 110%, rgba(255, 220, 74, 0.22), transparent 60%),
      var(--paper);
    font-family: var(--font-sans);
    -webkit-font-smoothing: antialiased;
    text-rendering: optimizeLegibility;
  }

  a { color: inherit; }

  .page {
    width: min(1140px, 100% - 2rem);
    margin: 0 auto;
    padding: 1.1rem 0 2.5rem;
  }

  .topbar {
    position: sticky;
    top: 0;
    z-index: 40;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding: 0.85rem 0;
    margin-bottom: 1rem;
    backdrop-filter: blur(8px);
  }

  .brand {
    display: inline-flex;
    align-items: center;
    gap: 0.7rem;
    text-decoration: none;
  }

  .brand-mark {
    width: 28px;
    height: 30px;
    position: relative;
    display: inline-block;
    clip-path: polygon(50% 2%, 90% 15%, 90% 57%, 50% 100%, 10% 57%, 10% 15%);
    background: linear-gradient(180deg, #ff8a34 0%, var(--smithery-orange) 56%, #d44300 100%);
    border: 1px solid rgba(123, 23, 7, 0.38);
    border-radius: 5px;
    box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.3);
  }

  .brand-mark::before {
    content: '';
    position: absolute;
    width: 9px;
    height: 13px;
    left: 8px;
    top: 6px;
    border-radius: 60% 60% 65% 65%;
    background: var(--smithery-white);
    transform: rotate(-8deg);
    clip-path: polygon(52% 0%, 78% 22%, 70% 48%, 90% 82%, 56% 100%, 24% 80%, 30% 52%, 18% 20%);
    opacity: 0.97;
  }

  .brand-mark::after {
    content: '';
    position: absolute;
    width: 4px;
    height: 6px;
    left: 10px;
    top: 9px;
    border-radius: 60%;
    background: var(--smithery-orange);
    transform: rotate(-9deg);
  }

  .brand-word {
    display: flex;
    align-items: baseline;
    gap: 0.45rem;
    flex-wrap: wrap;
  }

  .brand-word strong {
    font-size: 1.65rem;
    font-weight: 500;
    letter-spacing: -0.01em;
  }

  .brand-word small {
    color: var(--muted);
    font-size: 0.83rem;
    letter-spacing: 0.02em;
  }

  .mode-chip {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    background: var(--card-strong);
    border: 1px solid var(--line);
    padding: 0.35rem 0.68rem;
    border-radius: 999px;
    font-size: 0.82rem;
    white-space: nowrap;
  }

  .mode-chip .dot {
    width: 0.52rem;
    height: 0.52rem;
    border-radius: 50%;
    background: var(--smithery-orange);
  }

  .hero {
    padding: 0.4rem 0 0.8rem;
    display: grid;
    gap: 0.7rem;
  }

  .eyebrow {
    display: inline-flex;
    align-items: center;
    gap: 0.45rem;
    color: var(--smithery-orange);
    font-size: 0.83rem;
    letter-spacing: 0.045em;
    text-transform: uppercase;
    font-weight: 500;
  }

  .eyebrow::before {
    content: '';
    width: 0.65rem;
    height: 0.65rem;
    border-radius: 2px;
    background: var(--smithery-orange);
  }

  h1 {
    margin: 0;
    font-size: clamp(2rem, 5vw, 3.5rem);
    line-height: 0.97;
    letter-spacing: -0.02em;
    font-weight: 500;
    max-width: 16ch;
  }

  .subtitle {
    margin: 0;
    color: var(--muted);
    font-size: 1.08rem;
    line-height: 1.32;
    max-width: 62ch;
  }

  .metrics {
    display: flex;
    flex-wrap: wrap;
    gap: 0.58rem;
  }

  .pill {
    display: inline-flex;
    align-items: center;
    border-radius: 999px;
    padding: 0.24rem 0.62rem;
    border: 1px solid var(--line);
    background: var(--card);
    font-size: 0.84rem;
    gap: 0.35rem;
  }

  .pill strong { font-weight: 500; }

  .pill.warm {
    background: rgba(255, 220, 74, 0.28);
    border-color: rgba(255, 220, 74, 0.72);
  }

  .pill.hot {
    background: rgba(255, 86, 1, 0.12);
    border-color: rgba(255, 86, 1, 0.44);
  }

  .pill.success {
    background: rgba(123, 23, 7, 0.12);
    border-color: rgba(123, 23, 7, 0.34);
    color: var(--smithery-maroon);
  }

  .code-block,
  code,
  .mono {
    font-family: var(--font-mono);
  }

  .code-block {
    width: fit-content;
    max-width: 100%;
    background: var(--card-strong);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 0.74rem 0.85rem;
    font-size: 0.83rem;
    line-height: 1.4;
    overflow-x: auto;
  }

  .mode-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0.7rem;
    margin: 1rem 0;
  }

  .mode-card {
    border: 1px solid var(--line);
    border-radius: 12px;
    background: var(--card);
    padding: 0.82rem 0.9rem;
  }

  .mode-card h3 {
    margin: 0 0 0.35rem;
    font-size: 1rem;
    font-weight: 500;
  }

  .mode-card p {
    margin: 0;
    color: var(--muted);
    font-size: 0.9rem;
    line-height: 1.34;
  }

  .section {
    margin-top: 0.4rem;
  }

  .section h2 {
    margin: 0 0 0.35rem;
    font-size: clamp(1.3rem, 2.1vw, 1.8rem);
    font-weight: 500;
    letter-spacing: -0.01em;
  }

  .section > p {
    margin: 0;
    color: var(--muted);
  }

  .cards,
  .grid-3,
  .registry-grid,
  .stack {
    display: grid;
    gap: 0.8rem;
    margin-top: 0.9rem;
  }

  .stack { grid-template-columns: 1fr; max-width: 680px; }
  .grid-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .registry-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }

  .card {
    border: 1px solid var(--line);
    background: var(--card);
    border-radius: var(--radius);
    padding: 0.95rem;
    box-shadow: 0 1px 1px rgba(35, 35, 35, 0.04);
  }

  .card h3 {
    margin: 0;
    font-size: 1.12rem;
    font-weight: 500;
  }

  .card p {
    margin: 0.38rem 0 0;
    color: var(--muted);
    font-size: 0.94rem;
    line-height: 1.34;
  }

  .service-link {
    text-decoration: none;
    transition: transform 0.14s ease, border-color 0.14s ease, background 0.14s ease;
  }

  .service-link:hover {
    border-color: rgba(255, 86, 1, 0.35);
    background: var(--card-strong);
    transform: translateY(-1px);
  }

  .service-row {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 0.7rem;
  }

  .service-host {
    margin-top: 0.3rem;
    font-size: 0.79rem;
    color: #6b685f;
  }

  .service-blurb {
    margin-top: 0.52rem;
    font-size: 0.91rem;
    color: var(--muted);
    line-height: 1.34;
  }

  .service-icon {
    width: 54px;
    height: 54px;
    border-radius: 14px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 1.1rem;
    font-weight: 500;
    background: linear-gradient(145deg, rgba(255, 220, 74, 0.68), rgba(255, 86, 1, 0.35));
    border: 1px solid rgba(255, 86, 1, 0.26);
  }

  .service-hero {
    margin-top: 0.4rem;
    display: flex;
    align-items: center;
    gap: 0.85rem;
  }

  .service-hero h1 {
    max-width: none;
    font-size: clamp(1.8rem, 4vw, 2.8rem);
  }

  .service-hero .subtitle {
    font-size: 0.95rem;
  }

  .button-row {
    display: flex;
    flex-wrap: wrap;
    gap: 0.55rem;
    margin-top: 0.8rem;
  }

  .btn {
    appearance: none;
    border: 1px solid transparent;
    text-decoration: none;
    border-radius: 11px;
    padding: 0.52rem 0.76rem;
    font-size: 0.92rem;
    font-family: var(--font-sans);
    font-weight: 500;
    line-height: 1;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }

  .btn-primary {
    background: var(--smithery-orange);
    color: var(--smithery-white);
    border-color: rgba(123, 23, 7, 0.35);
  }

  .btn-primary:hover {
    background: #eb4f00;
  }

  .btn-secondary {
    background: var(--card-strong);
    border-color: var(--line);
    color: var(--ink);
  }

  .btn-secondary:hover {
    border-color: rgba(255, 86, 1, 0.45);
  }

  .btn-soft {
    background: rgba(255, 220, 74, 0.25);
    border-color: rgba(255, 220, 74, 0.6);
    color: var(--ink);
  }

  label,
  .label {
    font-size: 0.86rem;
    font-weight: 500;
    color: var(--muted);
    margin-bottom: 0.35rem;
    display: block;
  }

  input[type='text'],
  input[type='password'] {
    width: 100%;
    background: var(--smithery-white);
    border: 1px solid var(--line);
    border-radius: 11px;
    height: 42px;
    padding: 0 0.74rem;
    font-size: 0.88rem;
    font-family: var(--font-mono);
  }

  input:focus {
    outline: none;
    border-color: rgba(255, 86, 1, 0.5);
    box-shadow: 0 0 0 3px rgba(255, 86, 1, 0.13);
  }

  .form-group { margin-bottom: 0.8rem; }

  .token-box {
    margin-top: 0.55rem;
    border: 1px solid var(--line);
    border-radius: 11px;
    background: var(--smithery-white);
    padding: 0.65rem;
    font-size: 0.78rem;
    line-height: 1.45;
    word-break: break-all;
  }

  .error { color: var(--smithery-maroon); font-weight: 500; }

  ul.clean,
  ol.clean {
    margin: 0.58rem 0 0;
    padding: 0;
    list-style: none;
    display: grid;
    gap: 0.5rem;
  }

  ul.clean li,
  ol.clean li {
    border: 1px solid var(--line);
    background: rgba(255, 255, 255, 0.52);
    border-radius: 11px;
    padding: 0.56rem 0.66rem;
    font-size: 0.89rem;
    line-height: 1.35;
  }

  .doc-pre {
    margin: 0.6rem 0 0;
    padding: 0.8rem;
    border-radius: 12px;
    border: 1px solid var(--line);
    background: var(--smithery-white);
    overflow-x: auto;
    font-size: 0.78rem;
    line-height: 1.4;
  }

  .footnote {
    margin-top: 1rem;
    font-size: 0.78rem;
    color: #646056;
  }

  .status-row {
    display: flex;
    align-items: center;
    gap: 0.45rem;
    margin-top: 0.6rem;
    font-size: 0.88rem;
    color: var(--muted);
  }

  .status-dot {
    width: 0.52rem;
    height: 0.52rem;
    border-radius: 999px;
    background: #8a877d;
  }

  .status-dot.active { background: var(--smithery-orange); }
  .status-dot.ready { background: #4e8a37; }

  @media (max-width: 980px) {
    .grid-3 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .registry-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  }

  @media (max-width: 860px) {
    .mode-grid,
    .registry-grid,
    .grid-3 {
      grid-template-columns: 1fr;
    }

    .brand-word strong { font-size: 1.42rem; }

    .topbar {
      position: static;
      margin-bottom: 0.3rem;
      backdrop-filter: none;
    }
  }
`

function serviceName(service: ServiceRow) {
  return service.displayName ?? service.service
}

function serviceInitial(service: ServiceRow) {
  return serviceName(service).charAt(0).toUpperCase()
}

function parseSupportedAuth(service: ServiceRow) {
  if (!service.supportedAuthMethods) return [] as string[]
  try {
    const parsed = JSON.parse(service.supportedAuthMethods) as unknown
    return Array.isArray(parsed) ? parsed.filter(v => typeof v === 'string') : []
  } catch {
    return []
  }
}

function modeLabel(mode: 'human' | 'agent') {
  if (mode === 'agent') return 'Agent JSON Mode'
  return 'Human Readable Mode'
}

function Layout({
  children,
  title,
  mode = 'human',
}: {
  children: any
  title?: string
  mode?: 'human' | 'agent'
}) {
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{title ?? 'Warden'}</title>
        <style>{STYLES}</style>
      </head>
      <body>
        <div class="page">
          <header class="topbar">
            <a href="/" class="brand">
              <span class="brand-mark" aria-hidden="true"></span>
              <span class="brand-word">
                <strong>Warden</strong>
                <small>Smithery API Registry</small>
              </span>
            </a>
            <span class="mode-chip">
              <span class="dot"></span>
              {modeLabel(mode)}
            </span>
          </header>

          {children}

          <p class="footnote">
            Warden is a Smithery subproduct for secure API access and machine-ready discovery.
          </p>
        </div>
      </body>
    </html>
  )
}

function ModeSplit({
  human,
  agent,
}: {
  human: string
  agent: string
}) {
  return (
    <div class="mode-grid">
      <div class="mode-card">
        <h3>Human mode</h3>
        <p>{human}</p>
      </div>
      <div class="mode-card">
        <h3>Agent mode</h3>
        <p>{agent}</p>
      </div>
    </div>
  )
}

function RouteSpec({
  method,
  path,
  notes,
}: {
  method: string
  path: string
  notes: string
}) {
  return (
    <li>
      <span class="mono" style="font-size: 0.79rem">{method} {path}</span>
      <div style="margin-top: 0.18rem; color: var(--muted)">{notes}</div>
    </li>
  )
}

export function WardenLandingPage({ services = [] }: { services?: ServiceWithPopularity[] } = {}) {
  const ranked = [...services].sort((a, b) => {
    const byPopularity = (b.credentialCount ?? 0) - (a.credentialCount ?? 0)
    if (byPopularity !== 0) return byPopularity
    return serviceName(a).localeCompare(serviceName(b))
  })

  const credentialTotal = ranked.reduce((sum, service) => sum + (service.credentialCount ?? 0), 0)

  return (
    <Layout title="Warden — Smithery API Registry" mode="human">
      <section class="hero">
        <h1>Service Registry</h1>

        <div class="metrics">
          <span class="pill warm"><strong>{ranked.length}</strong> services</span>
          <span class="pill hot"><strong>{credentialTotal}</strong> credentials stored</span>
        </div>
      </section>

      <section class="section">
        {ranked.length === 0 ? (
          <div class="card">
            <h3>No services yet</h3>
            <p>Hit <span class="mono">/{'{hostname}'}</span> once to auto-register a service and start discovery.</p>
          </div>
        ) : (
          <div class="registry-grid">
            {ranked.map(service => (
              <a href={`/${service.service}`} class="card service-link">
                <div class="service-row">
                  <div>
                    <h3>{serviceName(service)}</h3>
                    <div class="service-host mono">{service.service}</div>
                  </div>
                  <span class="pill hot">
                    <strong>{service.credentialCount ?? 0}</strong> creds
                  </span>
                </div>
                <div class="service-blurb">{service.description ?? 'No description yet. Open to explore auth and docs.'}</div>
              </a>
            ))}
          </div>
        )}
      </section>
    </Layout>
  )
}

export function ServiceLandingPage({
  service,
  identity,
  credentialCount = 0,
  discoveryStatus,
}: {
  service: ServiceRow
  identity?: string
  credentialCount?: number
  discoveryStatus?: Record<string, unknown>
}) {
  const supported = parseSupportedAuth(service)
  const pipelineState = (discoveryStatus?.pipeline_state as string) ?? 'idle'
  const isActive = pipelineState === 'probing' || pipelineState === 'parsing' || pipelineState === 'enriching'
  const coverage = discoveryStatus?.coverage as
    | { total_resources?: number; total_operations?: number }
    | undefined
  const totalPages = Number(discoveryStatus?.total_pages ?? 0)
  const docsHref = `/${service.service}/docs/`

  const statusText = isActive
    ? `Discovery in progress (${pipelineState})`
    : `Discovery ready (${coverage?.total_resources ?? 0} resources, ${totalPages} pages)`

  return (
    <Layout title={`${serviceName(service)} — Warden`} mode="human">
      <section class="service-hero">
        <div class="service-icon">{serviceInitial(service)}</div>
        <div>
          <p class="eyebrow">Service Page</p>
          <h1>{serviceName(service)}</h1>
          <p class="subtitle mono">{service.service}</p>
        </div>
      </section>

      <div class="metrics" style="margin-top: 0.82rem">
        <span class="pill hot"><strong>{credentialCount}</strong> credentials stored</span>
        <span class="pill"><strong>{supported.length || 1}</strong> auth methods</span>
        <span class="pill"><strong>{service.apiType ?? 'unknown'}</strong> API type</span>
        <span class="pill"><strong>{totalPages}</strong> doc pages</span>
        {identity ? <span class="pill success">Connected as <strong>{identity}</strong></span> : null}
      </div>

      <ModeSplit
        human="Read about the service, connect credentials, and browse generated docs."
        agent={`GET /${service.service} with Accept: application/json for machine-readable discovery.`}
      />

      <div class="stack">
        <article class="card">
          <h3>About</h3>
          <p>{service.description ?? 'No service description yet. Warden can still handle auth and proxying.'}</p>
          <div class="status-row">
            <span class={`status-dot ${isActive ? 'active' : 'ready'}`}></span>
            <span>{statusText}</span>
          </div>
          <div class="button-row">
            <a class="btn btn-secondary" href={docsHref}>Open docs</a>
            {service.docsUrl ? (
              <a class="btn btn-secondary" href={service.docsUrl} target="_blank" rel="noopener noreferrer">Upstream docs</a>
            ) : null}
          </div>
        </article>

        <article class="card">
          <h3>Access</h3>
          {!identity ? (
            <>
              <p>Pick an auth path to connect credentials. Warden stores them and agents only receive revocable Warden tokens.</p>
              <div class="button-row">
                {supported.includes('oauth') ? (
                  <a href={`/auth/${service.service}/oauth`} class="btn btn-primary">Connect with OAuth</a>
                ) : null}
                {supported.includes('api_key') || supported.length === 0 ? (
                  <a href={`/auth/${service.service}/api-key`} class="btn btn-secondary">Enter API Key</a>
                ) : null}
              </div>
            </>
          ) : (
            <>
              <p>Your credential is connected. Agents can now call this service through Warden's proxy.</p>
              <div class="button-row">
                <a href={docsHref} class="btn btn-soft">Browse docs</a>
              </div>
            </>
          )}
        </article>

        <article class="card">
          <h3>Agent Reference</h3>
          <p>Routes and examples for agent integration:</p>
          <ol class="clean">
            <RouteSpec
              method="GET"
              path={`/${service.service}`}
              notes="Returns discovery payload, auth_url, and docs links in JSON."
            />
            <RouteSpec
              method="GET"
              path="/auth/status/{flow_id}"
              notes="Polls auth flow until token is ready."
            />
            <RouteSpec
              method="ANY"
              path={`/${service.service}/{path}`}
              notes="Proxy request with injected credentials using Bearer token."
            />
          </ol>
          <pre class="doc-pre"><code>{`curl -H "Accept: application/json" \\
  warden.run/${service.service}`}</code></pre>
          <pre class="doc-pre"><code>{`# then proxy using Warden token
curl -H "Authorization: Bearer <token>" \\
  warden.run/${service.service}/...`}</code></pre>
          {coverage?.total_resources ? (
            <p>Discovery coverage currently reports <strong>{coverage.total_resources}</strong> resources and <strong>{coverage.total_operations ?? 0}</strong> operations.</p>
          ) : (
            <p>Discovery coverage will appear here as docs are generated.</p>
          )}
        </article>
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
  const name = serviceName(service)

  return (
    <Layout title={`Connect ${name} — Warden`} mode="human">
      <section class="service-hero">
        <div class="service-icon">{serviceInitial(service)}</div>
        <div>
          <p class="eyebrow">Credential Setup</p>
          <h1>Connect {name}</h1>
          <p class="subtitle mono">flow_id={flowId}</p>
        </div>
      </section>

      <ModeSplit
        human="Paste your credential in this browser flow. The raw key is never passed back to the agent."
        agent="POST JSON to this endpoint with api_key + flow_id if you're automating key-based auth."
      />

      <div class="stack">
        <div class="card">
          <h3>Enter API Key</h3>
          <p>Warden encrypts this value and injects it at proxy time.</p>
          <form method="post" action={`/auth/${service.service}/api-key`} style="margin-top: 0.7rem">
            <input type="hidden" name="flow_id" value={flowId} />
            <div class="form-group">
              <label for="api_key">API Key</label>
              <input
                type="password"
                id="api_key"
                name="api_key"
                placeholder={`Paste your ${name} key`}
                required
                autocomplete="off"
                spellcheck={false}
              />
            </div>
            <button type="submit" class="btn btn-primary" style="width: 100%">Connect</button>
          </form>
          {service.docsUrl ? (
            <div class="button-row">
              <a href={service.docsUrl} target="_blank" rel="noopener noreferrer" class="btn btn-secondary">
                Find API key in upstream docs
              </a>
            </div>
          ) : null}
        </div>

        <div class="card">
          <h3>Agent Polling</h3>
          <p>After the user submits this form, agents poll for completion:</p>
          <pre class="doc-pre"><code>{`GET /auth/status/${flowId}`}</code></pre>
          <p>On completion, the response includes a revocable Warden token.</p>
        </div>
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
  const name = serviceName(service)

  return (
    <Layout title={`Connected to ${name} — Warden`} mode="human">
      <section class="service-hero">
        <div class="service-icon">{serviceInitial(service)}</div>
        <div>
          <p class="eyebrow">Connection Complete</p>
          <h1>{name} connected</h1>
          <p class="subtitle">Share this token with your agent. It can be revoked at any time.</p>
        </div>
      </section>

      <div class="card" style="margin-top: 1rem">
        <span class="label">Warden token</span>
        <div class="token-box" id="token">{token}</div>
        <div class="button-row">
          <button
            type="button"
            class="btn btn-primary"
            onclick="navigator.clipboard.writeText(document.getElementById('token').textContent.trim()).then(()=>{this.textContent='Copied';setTimeout(()=>{this.textContent='Copy token'},1800)})"
          >
            Copy token
          </button>
          <a href={`/${service.service}`} class="btn btn-secondary">Return to service page</a>
        </div>
      </div>
    </Layout>
  )
}

export function ErrorPage({ message }: { message: string }) {
  return (
    <Layout title="Error — Warden" mode="human">
      <section class="hero">
        <p class="eyebrow">Warden Error</p>
        <h1>Something failed</h1>
        <p class="subtitle">The request could not be completed. Details are below.</p>
      </section>

      <div class="card">
        <p class="error">{message}</p>
        <div class="button-row">
          <a href="/" class="btn btn-secondary">Back to registry</a>
        </div>
      </div>
    </Layout>
  )
}

function renderDocSummary(content: unknown) {
  if (!content || typeof content !== 'object') {
    return <p>Doc content is not structured JSON.</p>
  }

  const page = content as Record<string, unknown>
  const level = typeof page.level === 'number' ? page.level : undefined

  if (level === 0) {
    const auth = Array.isArray(page.auth) ? page.auth : []
    return (
      <>
        <p>{typeof page.description === 'string' && page.description.trim().length > 0 ? page.description : 'Service root documentation page.'}</p>
        {auth.length > 0 ? (
          <ul class="clean">
            {auth.map((method, index) => {
              const item = method as Record<string, unknown>
              return (
                <li>
                  <strong>{String(item.type ?? `method-${index + 1}`)}</strong>
                  <div class="mono" style="margin-top: 0.2rem; font-size: 0.8rem">{String(item.setup_url ?? '')}</div>
                </li>
              )
            })}
          </ul>
        ) : null}
      </>
    )
  }

  if (level === 1) {
    const resources = Array.isArray(page.resources) ? page.resources : []
    if (resources.length === 0) return <p>No resources listed yet.</p>

    return (
      <ul class="clean">
        {resources.map(resource => {
          const item = resource as Record<string, unknown>
          const commonOps = Array.isArray(item.common_operations) ? item.common_operations.length : 0
          return (
            <li>
              <strong>{String(item.name ?? item.slug ?? 'resource')}</strong>
              <div style="margin-top: 0.15rem">{String(item.description ?? 'No description')}</div>
              <div style="margin-top: 0.2rem" class="mono">{commonOps} common operations</div>
            </li>
          )
        })}
      </ul>
    )
  }

  if (level === 2) {
    const operations = Array.isArray(page.operations) ? page.operations : []
    if (operations.length === 0) return <p>No operations listed yet.</p>

    return (
      <ul class="clean">
        {operations.map(operation => {
          const item = operation as Record<string, unknown>
          return (
            <li>
              <span class="mono">{String(item.method ?? 'GET')} {String(item.path ?? '')}</span>
              <div style="margin-top: 0.16rem">{String(item.summary ?? 'No summary')}</div>
            </li>
          )
        })}
      </ul>
    )
  }

  if (level === 3) {
    return (
      <>
        <p>
          <span class="mono">{String(page.method ?? 'METHOD')} {String(page.path ?? '')}</span>
        </p>
        <p>{String(page.description ?? 'Operation details page.')}</p>
      </>
    )
  }

  return <p>Structured documentation page loaded.</p>
}

export function DocPageViewer({
  service,
  docPath,
  content,
  status,
}: {
  service: ServiceRow
  docPath: string
  content: unknown
  status?: string
}) {
  const json = JSON.stringify(content, null, 2)

  return (
    <Layout title={`${serviceName(service)} docs — ${docPath}`} mode="human">
      <section class="service-hero">
        <div class="service-icon">{serviceInitial(service)}</div>
        <div>
          <p class="eyebrow">Documentation</p>
          <h1>{serviceName(service)} docs</h1>
          <p class="subtitle mono">{service.service} / {docPath}</p>
        </div>
      </section>

      <ModeSplit
        human="Read this page as structured documentation with summaries and status."
        agent={`GET /${service.service}/${docPath} with Accept: application/json for raw machine content.`}
      />

      <div class="stack">
        <div class="card">
          <h3>Page Summary</h3>
          {renderDocSummary(content)}
          <div class="metrics" style="margin-top: 0.7rem">
            <span class="pill"><strong>path</strong> <span class="mono">{docPath}</span></span>
            <span class="pill"><strong>status</strong> {status ?? 'unknown'}</span>
          </div>
        </div>

        <div class="card">
          <h3>Raw JSON</h3>
          <p>Canonical agent representation for this doc page.</p>
          <pre class="doc-pre"><code>{json}</code></pre>
        </div>
      </div>
    </Layout>
  )
}
