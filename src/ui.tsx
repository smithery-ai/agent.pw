/** @jsxImportSource hono/jsx */
import type { InferSelectModel } from 'drizzle-orm'
import type { services } from './db/schema'
import { resolveServiceIconPreview } from './service-preview'

type ServiceRow = InferSelectModel<typeof services>
type ServiceWithPopularity = ServiceRow & { credentialCount?: number }

const STYLES = `
  :root {
    --background: #efead6;
    --foreground: #232323;
    --card: rgba(255, 255, 255, 0.78);
    --card-foreground: #232323;
    --muted: rgba(255, 255, 255, 0.94);
    --muted-foreground: #5a5750;
    --border: rgba(35, 35, 35, 0.16);
    --input: rgba(35, 35, 35, 0.16);
    --ring: rgba(255, 86, 1, 0.3);
    --primary: #ff5601;
    --primary-foreground: #ffffff;
    --secondary: rgba(255, 255, 255, 0.94);
    --secondary-foreground: #232323;
    --accent: #ffdc4a;
    --destructive: #7b1707;
    --success: #4e8a37;
    --radius: 0.5rem;

    --font-sans: 'GT Pantheon Micro', 'Iowan Old Style', 'Palatino Linotype', 'Book Antiqua', Georgia, serif;
    --font-mono: ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace;
  }

  *, *::before, *::after { box-sizing: border-box; }

  body {
    margin: 0;
    min-height: 100vh;
    color: var(--foreground);
    background: radial-gradient(1200px 520px at 92% -10%, rgba(255, 86, 1, 0.15), transparent 64%),
      radial-gradient(900px 460px at -8% 110%, rgba(255, 220, 74, 0.22), transparent 60%),
      var(--background);
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
    height: 32px;
    display: inline-block;
    flex-shrink: 0;
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
    color: var(--muted-foreground);
    font-size: 0.83rem;
    letter-spacing: 0.02em;
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
    color: var(--primary);
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
    background: var(--primary);
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
    color: var(--muted-foreground);
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
    border: 1px solid var(--border);
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
    color: var(--destructive);
  }

  .code-block,
  code,
  .mono {
    font-family: var(--font-mono);
  }

  .code-block {
    width: fit-content;
    max-width: 100%;
    background: var(--muted);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 0.74rem 0.85rem;
    font-size: 0.83rem;
    line-height: 1.4;
    overflow-x: auto;
  }

  .copyable {
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 0.7rem;
    transition: border-color 0.14s ease;
  }

  .copyable:hover { border-color: rgba(255, 86, 1, 0.45); }

  .copy-hint {
    color: var(--muted-foreground);
    font-size: 0.74rem;
    font-family: var(--font-sans);
    white-space: nowrap;
  }

  .copyable.copied .copy-hint::after { content: ' — copied!'; }

  .mode-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0.7rem;
    margin: 1rem 0;
  }

  .mode-card {
    border: 1px solid var(--border);
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
    color: var(--muted-foreground);
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
    color: var(--muted-foreground);
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
    border: 1px solid var(--border);
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
    color: var(--muted-foreground);
    font-size: 0.94rem;
    line-height: 1.34;
  }

  .service-link {
    text-decoration: none;
    transition: transform 0.14s ease, border-color 0.14s ease, background 0.14s ease;
  }

  .service-link:hover {
    border-color: rgba(255, 86, 1, 0.35);
    background: var(--muted);
    transform: translateY(-1px);
  }

  .service-row {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 0.7rem;
  }

  .service-main {
    display: flex;
    align-items: center;
    gap: 0.72rem;
    min-width: 0;
  }

  .service-main > div { min-width: 0; }

  .service-host {
    margin-top: 0.3rem;
    font-size: 0.79rem;
    color: #6b685f;
    overflow-wrap: anywhere;
  }

  .service-blurb {
    margin-top: 0.52rem;
    font-size: 0.91rem;
    color: var(--muted-foreground);
    line-height: 1.34;
  }

  .service-icon {
    width: 54px;
    height: 54px;
    border-radius: 14px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    position: relative;
    overflow: hidden;
    flex-shrink: 0;
    font-size: 1rem;
    font-weight: 600;
    letter-spacing: 0.02em;
    background: linear-gradient(145deg, rgba(255, 220, 74, 0.68), rgba(255, 86, 1, 0.35));
    border: 1px solid rgba(255, 86, 1, 0.26);
  }

  .service-icon img {
    width: 30px;
    height: 30px;
    object-fit: contain;
    border-radius: 7px;
  }

  .service-icon-fallback {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    line-height: 1;
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
    background: var(--primary);
    color: var(--primary-foreground);
    border-color: rgba(123, 23, 7, 0.35);
  }

  .btn-primary:hover {
    background: #eb4f00;
  }

  .btn-secondary {
    background: var(--muted);
    border-color: var(--border);
    color: var(--foreground);
  }

  .btn-secondary:hover {
    border-color: rgba(255, 86, 1, 0.45);
  }

  .btn-soft {
    background: rgba(255, 220, 74, 0.25);
    border-color: rgba(255, 220, 74, 0.6);
    color: var(--foreground);
  }

  label,
  .label {
    font-size: 0.86rem;
    font-weight: 500;
    color: var(--muted-foreground);
    margin-bottom: 0.35rem;
    display: block;
  }

  input[type='text'],
  input[type='password'] {
    width: 100%;
    background: var(--primary-foreground);
    border: 1px solid var(--border);
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
    border: 1px solid var(--border);
    border-radius: 11px;
    background: var(--primary-foreground);
    padding: 0.65rem;
    font-size: 0.78rem;
    line-height: 1.45;
    word-break: break-all;
  }

  .error { color: var(--destructive); font-weight: 500; }

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
    border: 1px solid var(--border);
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
    border: 1px solid var(--border);
    background: var(--primary-foreground);
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
    color: var(--muted-foreground);
  }

  .status-dot {
    width: 0.52rem;
    height: 0.52rem;
    border-radius: 999px;
    background: #8a877d;
  }

  .status-dot.active { background: var(--primary); }
  .status-dot.ready { background: var(--success); }

  .credential-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.84rem;
    padding: 0.4rem 0.55rem;
    border-radius: var(--radius);
    background: var(--muted);
  }

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

function parseServicePreview(service: ServiceRow) {
  if (!service.preview) return undefined
  try {
    return JSON.parse(service.preview) as unknown
  } catch {
    return undefined
  }
}

function ServiceIcon({ service }: { service: ServiceRow }) {
  const icon = resolveServiceIconPreview(service.service, parseServicePreview(service), serviceName(service))
  const alt = `${serviceName(service)} icon`

  return (
    <div class="service-icon" title={service.service}>
      {icon.url ? (
        <>
          <img
            src={icon.url}
            alt={alt}
            loading="lazy"
            onerror="this.style.display='none'; this.nextElementSibling.style.display='inline-flex';"
          />
          <span class="service-icon-fallback" style="display:none">{icon.fallback}</span>
        </>
      ) : (
        <span class="service-icon-fallback">{icon.fallback}</span>
      )}
    </div>
  )
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

function Layout({
  children,
  title,
}: {
  children: any
  title?: string
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
              <svg class="brand-mark" viewBox="0 0 188 211" fill="var(--primary)" aria-hidden="true">
                <path d="M41.7011 77.48H0V100.264C0 118.171 14.5275 132.698 32.4342 132.698H55.2183V90.9971C55.2183 83.5418 49.1565 77.48 41.7011 77.48Z"/>
                <path d="M66.0879 90.9971V132.698H107.789C115.244 132.698 121.306 126.636 121.306 119.181V77.48H79.6051C72.1497 77.48 66.0879 83.5418 66.0879 90.9971Z"/>
                <path d="M154.995 77.48H132.21V119.181C132.21 126.636 138.272 132.698 145.728 132.698H187.429V106.152C187.429 88.2449 172.901 77.5148 154.995 77.5148V77.48Z"/>
                <path d="M0 45.9514V66.6103H41.7011C49.1565 66.6103 55.2183 60.5485 55.2183 53.0932V0C25.8498 0.209028 0.034838 14.6668 0 45.9514Z"/>
                <path d="M66.0879 53.093C66.0879 60.5483 72.1497 66.6101 79.6051 66.6101H121.306V11.4615C100.926 8.36092 90.3003 1.74169 66.0879 0.243652V53.0581V53.093Z"/>
                <path d="M144.09 13.0639C139.77 13.0639 135.834 12.9246 132.21 12.6807V66.61H154.995C172.901 66.61 187.429 52.0825 187.429 34.1758V0.173828C177.291 8.1169 162.903 13.0639 144.09 13.0639Z"/>
                <path d="M0 176.002V210.004C10.1379 202.061 24.526 197.114 43.3385 197.114C47.6584 197.114 51.5951 197.253 55.2183 197.532V143.603H32.4342C14.5275 143.603 0 158.13 0 176.037L0 176.002Z"/>
                <path d="M107.789 143.603H66.0879V198.716C86.4681 201.817 97.0938 208.436 121.306 209.934V157.12C121.306 149.664 115.244 143.603 107.789 143.603Z"/>
                <path d="M132.21 157.085V210.178C161.544 209.969 187.324 195.511 187.429 164.296V143.568H145.728C138.272 143.568 132.21 149.63 132.21 157.085Z"/>
              </svg>
              <span class="brand-word">
                <strong>Warden</strong>
                <small>Smithery API Registry</small>
              </span>
            </a>
          </header>

          {children}

          <p class="footnote">
            Forged with &lt;3 by Smithery
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
      <div style="margin-top: 0.18rem; color: var(--muted-foreground)">{notes}</div>
    </li>
  )
}

export function WardenLandingPage({ services = [] }: { services?: ServiceWithPopularity[] } = {}) {
  const withCreds = services.filter(s => (s.credentialCount ?? 0) > 0)
  const ranked = [...withCreds].sort((a, b) => {
    const byPopularity = (b.credentialCount ?? 0) - (a.credentialCount ?? 0)
    if (byPopularity !== 0) return byPopularity
    return serviceName(a).localeCompare(serviceName(b))
  })

  const credentialTotal = ranked.reduce((sum, service) => sum + (service.credentialCount ?? 0), 0)

  return (
    <Layout title="Warden — Smithery API Registry">
      <section class="hero">
        <h1>Service Registry</h1>
        <div class="code-block copyable" onclick="navigator.clipboard.writeText(this.querySelector('span').textContent.trim()).then(()=>{this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),1800)})">
          <span class="mono">curl https://warden.run and help me connect to services</span>
          <small class="copy-hint">click to copy</small>
        </div>
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
                  <div class="service-main">
                    <ServiceIcon service={service} />
                    <div>
                      <h3>{serviceName(service)}</h3>
                      <div class="service-host mono">{service.service}</div>
                    </div>
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
  credentialCount = 0,
  discoveryStatus,
  userCredentials,
}: {
  service: ServiceRow
  credentialCount?: number
  discoveryStatus?: Record<string, unknown>
  userCredentials?: { slug: string; updatedAt: Date }[]
}) {
  const hasCredentials = (userCredentials?.length ?? 0) > 0
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
    <Layout title={`${serviceName(service)} — Warden`}>
      <section class="service-hero">
        <ServiceIcon service={service} />
        <div>
          <p class="eyebrow">Service Page</p>
          <h1>{serviceName(service)}</h1>
          <p class="subtitle mono">{service.service}</p>
        </div>
      </section>

      {hasCredentials ? (
        <article class="card" style="margin-top: 0.82rem">
          <span class="label">Your credentials</span>
          <ul class="clean">
            {(userCredentials ?? []).map(credential => (
              <li>
                <span class="mono">{credential.slug}</span>
                <span style="float: right; color: var(--muted);">{formatTimeAgo(credential.updatedAt)}</span>
              </li>
            ))}
          </ul>
        </article>
      ) : null}

      <div class="code-block copyable" style="margin-top: 0.82rem" onclick="navigator.clipboard.writeText(this.querySelector('span').textContent.trim()).then(()=>{this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),1800)})">
        <span class="mono">{`curl https://warden.run/${service.service} and help me use ${serviceName(service)}`}</span>
        <small class="copy-hint">click to copy</small>
      </div>

      <div class="metrics" style="margin-top: 0.82rem">
        <span class="pill hot"><strong>{credentialCount}</strong> credentials stored</span>
        <span class="pill"><strong>{supported.length || 1}</strong> auth methods</span>
        <span class="pill"><strong>{service.apiType ?? 'unknown'}</strong> API type</span>
        <span class="pill"><strong>{totalPages}</strong> doc pages</span>
        {hasCredentials ? <span class="pill success">Connected <strong>{userCredentials?.length ?? 0}</strong></span> : null}
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
          {!hasCredentials ? (
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
    <Layout title={`Connect ${name} — Warden`}>
      <section class="service-hero">
        <ServiceIcon service={service} />
        <div>
          <p class="eyebrow">Credential Setup</p>
          <h1>Connect {name}</h1>
          <p class="subtitle mono">flow_id={flowId}</p>
        </div>
      </section>

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
    <Layout title={`Connected to ${name} — Warden`}>
      <section class="service-hero">
        <ServiceIcon service={service} />
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
    <Layout title={`${serviceName(service)} docs — ${docPath}`}>
      <section class="service-hero">
        <ServiceIcon service={service} />
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
