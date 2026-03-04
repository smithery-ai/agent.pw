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
    --border: rgba(35, 35, 35, 0.13);
    --input: rgba(35, 35, 35, 0.16);
    --ring: rgba(255, 86, 1, 0.3);
    --primary: #ff5601;
    --primary-foreground: #ffffff;
    --secondary: rgba(255, 255, 255, 0.94);
    --secondary-foreground: #232323;
    --accent: #ffdc4a;
    --destructive: #7b1707;
    --success: #4e8a37;
    --radius: 0.625rem;

    --font-sans: 'GT Pantheon Micro', 'Iowan Old Style', 'Palatino Linotype', 'Book Antiqua', Georgia, serif;
    --font-mono: 'Berkeley Mono', 'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
  }

  *, *::before, *::after { box-sizing: border-box; }

  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(12px); }
    to { opacity: 1; transform: translateY(0); }
  }

  @keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }

  body {
    margin: 0;
    min-height: 100vh;
    color: var(--foreground);
    background: var(--background);
    font-family: var(--font-sans);
    -webkit-font-smoothing: antialiased;
    text-rendering: optimizeLegibility;
  }

  body::before {
    content: '';
    position: fixed;
    inset: 0;
    z-index: 0;
    pointer-events: none;
    background:
      radial-gradient(1400px 600px at 95% -15%, rgba(255, 86, 1, 0.13), transparent 60%),
      radial-gradient(1000px 500px at -5% 105%, rgba(255, 220, 74, 0.18), transparent 55%);
  }

  body::after {
    content: '';
    position: fixed;
    inset: 0;
    z-index: 1;
    pointer-events: none;
    opacity: 0.28;
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='1'/%3E%3C/svg%3E");
    background-repeat: repeat;
    background-size: 180px;
  }

  a { color: inherit; }

  .page {
    position: relative;
    z-index: 2;
    width: min(1140px, 100% - 2.5rem);
    margin: 0 auto;
    padding: 1.1rem 0 3rem;
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
    margin-bottom: 1.2rem;
    backdrop-filter: blur(12px) saturate(1.4);
    border-bottom: 1px solid var(--border);
    animation: fadeIn 0.5s ease both;
  }

  .brand {
    display: inline-flex;
    align-items: center;
    gap: 0.7rem;
    text-decoration: none;
    transition: opacity 0.2s ease;
  }

  .brand:hover { opacity: 0.72; }

  .brand-mark {
    width: 30px;
    height: 34px;
    display: inline-block;
    flex-shrink: 0;
    filter: drop-shadow(0 1px 3px rgba(255, 86, 1, 0.25));
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
    letter-spacing: -0.015em;
  }

  .brand-word small {
    color: var(--muted-foreground);
    font-size: 0.82rem;
    letter-spacing: 0.03em;
  }

  .hero {
    padding: 0.8rem 0 1rem;
    display: grid;
    gap: 0.8rem;
    animation: fadeUp 0.55s ease both;
  }

  .eyebrow {
    display: inline-flex;
    align-items: center;
    gap: 0.45rem;
    color: var(--primary);
    font-size: 0.8rem;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    font-weight: 600;
  }

  .eyebrow::before {
    content: '';
    width: 0.55rem;
    height: 0.55rem;
    border-radius: 2px;
    background: var(--primary);
    box-shadow: 0 0 6px rgba(255, 86, 1, 0.4);
  }

  h1 {
    margin: 0;
    font-size: clamp(2.2rem, 5.5vw, 3.8rem);
    line-height: 0.95;
    letter-spacing: -0.025em;
    font-weight: 500;
    max-width: 16ch;
  }

  .subtitle {
    margin: 0;
    color: var(--muted-foreground);
    font-size: 1.08rem;
    line-height: 1.36;
    max-width: 62ch;
  }

  .metrics {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    animation: fadeIn 0.6s ease 0.2s both;
  }

  .pill {
    display: inline-flex;
    align-items: center;
    border-radius: 999px;
    padding: 0.28rem 0.68rem;
    border: 1px solid var(--border);
    background: rgba(255, 255, 255, 0.6);
    backdrop-filter: blur(6px);
    font-size: 0.82rem;
    gap: 0.35rem;
  }

  .pill strong { font-weight: 600; }

  .pill.warm {
    background: rgba(255, 220, 74, 0.25);
    border-color: rgba(255, 220, 74, 0.6);
  }

  .pill.hot {
    background: rgba(255, 86, 1, 0.1);
    border-color: rgba(255, 86, 1, 0.35);
  }

  .pill.success {
    background: rgba(78, 138, 55, 0.1);
    border-color: rgba(78, 138, 55, 0.35);
    color: var(--success);
  }

  .code-block,
  code,
  .mono {
    font-family: var(--font-mono);
  }

  .code-block {
    width: fit-content;
    max-width: 100%;
    background: rgba(255, 255, 255, 0.55);
    backdrop-filter: blur(6px);
    border: 1px solid var(--border);
    border-left: 3px solid var(--primary);
    border-radius: var(--radius);
    padding: 0.78rem 0.92rem;
    font-size: 0.82rem;
    line-height: 1.45;
    overflow-x: auto;
  }

  .copyable {
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 0.7rem;
    transition: border-color 0.18s ease, box-shadow 0.18s ease, transform 0.18s ease;
  }

  .copyable:hover {
    border-color: rgba(255, 86, 1, 0.4);
    box-shadow: 0 2px 12px rgba(255, 86, 1, 0.08);
    transform: translateY(-1px);
  }

  .copyable:active { transform: scale(0.995); }

  .copy-hint {
    color: var(--muted-foreground);
    font-size: 0.72rem;
    font-family: var(--font-sans);
    white-space: nowrap;
    opacity: 0.7;
    transition: opacity 0.15s ease;
  }

  .copyable:hover .copy-hint { opacity: 1; }

  .copyable.copied .copy-hint::after {
    content: ' \u2014 copied!';
    color: var(--success);
  }

  .section {
    margin-top: 0.6rem;
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

  .registry-grid > *,
  .stack > * {
    animation: fadeUp 0.45s ease both;
  }

  .registry-grid > *:nth-child(1) { animation-delay: 0.06s; }
  .registry-grid > *:nth-child(2) { animation-delay: 0.12s; }
  .registry-grid > *:nth-child(3) { animation-delay: 0.18s; }
  .registry-grid > *:nth-child(4) { animation-delay: 0.22s; }
  .registry-grid > *:nth-child(5) { animation-delay: 0.26s; }
  .registry-grid > *:nth-child(6) { animation-delay: 0.30s; }
  .registry-grid > *:nth-child(n+7) { animation-delay: 0.34s; }

  .stack > *:nth-child(1) { animation-delay: 0.08s; }
  .stack > *:nth-child(2) { animation-delay: 0.16s; }
  .stack > *:nth-child(3) { animation-delay: 0.24s; }
  .stack > *:nth-child(n+4) { animation-delay: 0.30s; }

  .card {
    border: 1px solid var(--border);
    background: var(--card);
    border-radius: var(--radius);
    padding: 1rem 1.05rem;
    box-shadow:
      0 1px 2px rgba(35, 35, 35, 0.04),
      0 4px 16px rgba(35, 35, 35, 0.03);
    transition: box-shadow 0.22s ease, border-color 0.22s ease;
  }

  .card h3 {
    margin: 0;
    font-size: 1.1rem;
    font-weight: 600;
    letter-spacing: -0.005em;
  }

  .card p {
    margin: 0.38rem 0 0;
    color: var(--muted-foreground);
    font-size: 0.93rem;
    line-height: 1.38;
  }

  .service-link {
    text-decoration: none;
    transition: transform 0.22s ease, border-color 0.22s ease, box-shadow 0.22s ease;
  }

  .service-link:hover {
    border-color: rgba(255, 86, 1, 0.3);
    box-shadow:
      0 4px 20px rgba(255, 86, 1, 0.07),
      0 1px 3px rgba(35, 35, 35, 0.06);
    transform: translateY(-2px);
  }

  .service-link:hover .service-icon {
    box-shadow: 0 0 16px rgba(255, 86, 1, 0.2);
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
    margin-top: 0.28rem;
    font-size: 0.77rem;
    color: #6b685f;
    overflow-wrap: anywhere;
  }

  .service-blurb {
    margin-top: 0.52rem;
    font-size: 0.9rem;
    color: var(--muted-foreground);
    line-height: 1.38;
  }

  .service-icon {
    width: 52px;
    height: 52px;
    border-radius: 13px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    position: relative;
    overflow: hidden;
    flex-shrink: 0;
    font-size: 1rem;
    font-weight: 600;
    letter-spacing: 0.02em;
    background: linear-gradient(145deg, rgba(255, 220, 74, 0.65), rgba(255, 86, 1, 0.32));
    border: 1px solid rgba(255, 86, 1, 0.22);
    transition: box-shadow 0.22s ease;
  }

  .service-icon img {
    width: 28px;
    height: 28px;
    object-fit: contain;
    border-radius: 6px;
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
    gap: 0.9rem;
    animation: fadeUp 0.5s ease both;
  }

  .service-hero .service-icon {
    width: 64px;
    height: 64px;
    border-radius: 16px;
    font-size: 1.2rem;
    box-shadow: 0 4px 20px rgba(255, 86, 1, 0.12);
  }

  .service-hero .service-icon img {
    width: 36px;
    height: 36px;
  }

  .service-hero h1 {
    max-width: none;
    font-size: clamp(1.8rem, 4vw, 2.8rem);
  }

  .service-hero .subtitle {
    font-size: 0.93rem;
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
    border-radius: var(--radius);
    padding: 0.54rem 0.82rem;
    font-size: 0.9rem;
    font-family: var(--font-sans);
    font-weight: 500;
    line-height: 1;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    transition: transform 0.15s ease, box-shadow 0.15s ease, background 0.15s ease, border-color 0.15s ease;
  }

  .btn:active { transform: scale(0.97); }

  .btn-primary {
    background: var(--primary);
    color: var(--primary-foreground);
    border-color: rgba(123, 23, 7, 0.3);
    box-shadow: 0 1px 3px rgba(255, 86, 1, 0.2);
  }

  .btn-primary:hover {
    background: #eb4f00;
    box-shadow: 0 2px 8px rgba(255, 86, 1, 0.25);
    transform: translateY(-1px);
  }

  .btn-secondary {
    background: var(--muted);
    border-color: var(--border);
    color: var(--foreground);
  }

  .btn-secondary:hover {
    border-color: rgba(255, 86, 1, 0.35);
    box-shadow: 0 1px 4px rgba(35, 35, 35, 0.06);
    transform: translateY(-1px);
  }

  .btn-soft {
    background: rgba(255, 220, 74, 0.22);
    border-color: rgba(255, 220, 74, 0.5);
    color: var(--foreground);
  }

  .btn-soft:hover {
    background: rgba(255, 220, 74, 0.32);
    transform: translateY(-1px);
  }

  label,
  .label {
    font-size: 0.84rem;
    font-weight: 600;
    color: var(--muted-foreground);
    margin-bottom: 0.35rem;
    display: block;
    letter-spacing: 0.01em;
  }

  input[type='text'],
  input[type='password'] {
    width: 100%;
    background: var(--primary-foreground);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    height: 44px;
    padding: 0 0.78rem;
    font-size: 0.86rem;
    font-family: var(--font-mono);
    transition: border-color 0.18s ease, box-shadow 0.18s ease;
  }

  input:focus {
    outline: none;
    border-color: rgba(255, 86, 1, 0.5);
    box-shadow: 0 0 0 3px rgba(255, 86, 1, 0.1);
  }

  .form-group { margin-bottom: 0.85rem; }

  .token-box {
    margin-top: 0.55rem;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--primary-foreground);
    padding: 0.7rem;
    font-size: 0.76rem;
    font-family: var(--font-mono);
    line-height: 1.5;
    word-break: break-all;
  }

  .error { color: var(--destructive); font-weight: 500; }

  ul.clean,
  ol.clean {
    margin: 0.58rem 0 0;
    padding: 0;
    list-style: none;
    display: grid;
    gap: 0.45rem;
  }

  ul.clean li,
  ol.clean li {
    border: 1px solid var(--border);
    background: rgba(255, 255, 255, 0.5);
    border-radius: var(--radius);
    padding: 0.58rem 0.7rem;
    font-size: 0.88rem;
    line-height: 1.38;
    transition: border-color 0.15s ease;
  }

  ul.clean li:hover,
  ol.clean li:hover {
    border-color: rgba(255, 86, 1, 0.2);
  }

  .doc-pre {
    margin: 0.6rem 0 0;
    padding: 0.85rem;
    border-radius: var(--radius);
    border: 1px solid rgba(50, 44, 36, 0.2);
    background: #2a2520;
    color: #e8e2d0;
    overflow-x: auto;
    font-size: 0.77rem;
    line-height: 1.45;
  }

  .footnote {
    margin-top: 2.5rem;
    padding-top: 1.2rem;
    border-top: 1px solid var(--border);
    font-size: 0.78rem;
    color: #8a8578;
    letter-spacing: 0.01em;
  }

  .status-row {
    display: flex;
    align-items: center;
    gap: 0.45rem;
    margin-top: 0.6rem;
    font-size: 0.86rem;
    color: var(--muted-foreground);
  }

  .status-dot {
    width: 0.5rem;
    height: 0.5rem;
    border-radius: 999px;
    background: #8a877d;
  }

  .status-dot.active {
    background: var(--primary);
    animation: pulse 1.8s ease-in-out infinite;
    box-shadow: 0 0 6px rgba(255, 86, 1, 0.4);
  }

  .status-dot.ready {
    background: var(--success);
    box-shadow: 0 0 4px rgba(78, 138, 55, 0.3);
  }

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

    .service-hero .service-icon {
      width: 52px;
      height: 52px;
    }

    .service-hero .service-icon img {
      width: 28px;
      height: 28px;
    }
  }

  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
      animation-duration: 0.01ms !important;
      transition-duration: 0.01ms !important;
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
                <defs>
                  <clipPath id="shield">
                    <path d="M12 0H176Q188 0 188 12V115Q188 185 94 211Q0 185 0 115V12Q0 0 12 0Z"/>
                  </clipPath>
                </defs>
                <g clip-path="url(#shield)">
                  <rect x="-10" y="-10" width="64" height="68" rx="10"/>
                  <rect x="68" y="-10" width="52" height="68" rx="10"/>
                  <rect x="134" y="-10" width="64" height="68" rx="10"/>
                  <rect x="-10" y="72" width="64" height="66" rx="10"/>
                  <rect x="68" y="72" width="52" height="66" rx="10"/>
                  <rect x="134" y="72" width="64" height="66" rx="10"/>
                  <rect x="-10" y="152" width="64" height="69" rx="10"/>
                  <rect x="68" y="152" width="52" height="69" rx="10"/>
                  <rect x="134" y="152" width="64" height="69" rx="10"/>
                </g>
              </svg>
              <span class="brand-word">
                <strong>Warden</strong>
                <small>Connect agents to services securely</small>
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

export function WardenLandingPage({ services = [], userCount = 0 }: { services?: ServiceWithPopularity[]; userCount?: number } = {}) {
  const withCreds = services.filter(s => (s.credentialCount ?? 0) > 0)
  const ranked = [...withCreds].sort((a, b) => {
    const byPopularity = (b.credentialCount ?? 0) - (a.credentialCount ?? 0)
    if (byPopularity !== 0) return byPopularity
    return serviceName(a).localeCompare(serviceName(b))
  })

  return (
    <Layout title="Warden — Connect agents to services securely">
      <section class="hero">
        <h1>Service Registry</h1>
        <div class="code-block copyable" onclick="navigator.clipboard.writeText(this.querySelector('span').textContent.trim()).then(()=>{this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),1800)})">
          <span class="mono">curl https://warden.run and help me connect to services</span>
          <small class="copy-hint">click to copy</small>
        </div>
        <div class="metrics">
          <span class="pill warm"><strong>{ranked.length}</strong> services</span>
          <span class="pill">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
            <strong>{userCount}</strong> users
          </span>
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
