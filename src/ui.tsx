/** @jsxImportSource hono/jsx */
import type { InferSelectModel } from 'drizzle-orm'
import type { services } from './db/schema'
import { resolveServiceIconPreview } from './service-preview'
import { parseAuthSchemes, getOAuthScheme, getApiKeyScheme } from './auth-schemes'

type ServiceRow = InferSelectModel<typeof services>
type ServiceWithPopularity = ServiceRow & { credentialCount?: number }

const STYLES = `
  :root {
    --background: #efead6;
    --foreground: #232323;
    --card: rgba(255, 255, 255, 0.88);
    --card-foreground: #232323;
    --muted: rgba(255, 255, 255, 0.94);
    --muted-foreground: #5a5750;
    --border: rgba(35, 35, 35, 0.10);
    --input: rgba(35, 35, 35, 0.16);
    --ring: rgba(255, 86, 1, 0.3);
    --primary: #ff5601;
    --primary-foreground: #ffffff;
    --secondary: rgba(255, 255, 255, 0.94);
    --secondary-foreground: #232323;
    --accent: #ffdc4a;
    --destructive: #7b1707;
    --success: #4e8a37;
    --radius: 0.75rem;

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


  .hero {
    padding: 1.5rem 0 2rem;
    display: grid;
    gap: 1.2rem;
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
    gap: 0.6rem;
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
    background: #2a2520;
    color: #e8e2d0;
    border: 1px solid rgba(50, 44, 36, 0.2);
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
    border-color: rgba(255, 86, 1, 0.3);
    box-shadow: 0 2px 16px rgba(0, 0, 0, 0.12);
    transform: translateY(-1px);
  }

  .copyable:active { transform: scale(0.995); }

  .copy-icon {
    color: #8a8578;
    flex-shrink: 0;
    opacity: 0.5;
    transition: opacity 0.15s ease;
  }

  .copyable:hover .copy-icon { opacity: 0.85; }

  .copy-icon .icon-check { display: none; }
  .copyable.copied .copy-icon .icon-copy { display: none; }
  .copyable.copied .copy-icon .icon-check { display: block; color: var(--success); }

  .copy-hint {
    display: none;
    margin-left: 0.08rem;
    font-size: 0.66rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: var(--success);
  }

  .copyable.copied .copy-hint { display: inline-flex; }

  .section {
    margin-top: 1.5rem;
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
  .two-col,
  .grid-3,
  .registry-grid,
  .stack {
    display: grid;
    gap: 1rem;
    margin-top: 1.2rem;
  }

  .stack { grid-template-columns: 1fr; max-width: 680px; }

  .two-col {
    display: grid;
    grid-template-columns: 1fr 340px;
    gap: 3rem;
    margin-top: 0.5rem;
    align-items: start;
  }

  .two-col > .col-left,
  .two-col > .col-right {
    display: grid;
    gap: 0;
  }

  .two-col > .col-left {
    animation: fadeUp 0.45s ease 0.06s both;
  }

  .two-col > .col-right {
    animation: fadeUp 0.45s ease 0.12s both;
  }

  .col-right .code-block { width: 100%; }

  .col-section {
    padding: 1.8rem 0;
    border-top: 1px solid var(--border);
  }

  .col-section:first-child {
    padding-top: 0;
    border-top: none;
  }

  .col-section h3 {
    margin: 0 0 0.55rem;
    font-size: 1rem;
    font-weight: 600;
    letter-spacing: -0.005em;
  }

  .col-section p {
    margin: 0.4rem 0 0;
    color: var(--muted-foreground);
    font-size: 0.9rem;
    line-height: 1.48;
  }

  .connect-label {
    font-size: 0.72rem;
    font-weight: 600;
    color: var(--muted-foreground);
    letter-spacing: 0.05em;
    text-transform: uppercase;
    margin-bottom: 0.35rem;
  }

  .credential-list {
    margin: 0;
    padding: 0;
    list-style: none;
    display: grid;
    gap: 0;
  }

  .credential-list li {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.5rem 0;
    border-bottom: 1px solid var(--border);
    font-size: 0.86rem;
  }

  .credential-list li:last-child { border-bottom: none; }

  .meta-line {
    font-size: 0.8rem;
    color: var(--muted-foreground);
    margin-top: 0.25rem;
  }

  .meta-line a { text-decoration: underline; text-underline-offset: 2px; }
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
    padding: 1.1rem 1.2rem;
    box-shadow: 0 1px 3px rgba(35, 35, 35, 0.04);
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
    border-color: rgba(255, 86, 1, 0.3);
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
    background: var(--muted);
    border: 1px solid var(--border);
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
    margin-bottom: 1.4rem;
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
    padding: 0.58rem 0.9rem;
    font-size: 0.88rem;
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

  .badge {
    display: inline-block; padding: 0.125rem 0.4rem; border-radius: 4px;
    font-size: 0.75rem; font-weight: 500; background: #052e16; color: var(--success);
    font-family: 'SF Mono', SFMono-Regular, ui-monospace, monospace;
  }
  .error { color: var(--destructive); font-weight: 500; }
  .auth-options { display: flex; flex-direction: column; gap: 0.5rem; }
  .tab-list {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(0, 1fr));
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
  .tab-panel {
    display: none;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: #0c0c0f;
    padding: 1rem;
  }
  #tab-oauth:checked ~ .tab-list [for="tab-oauth"],
  #tab-api:checked ~ .tab-list [for="tab-api"] {
    border-color: #71717a; background: #27272a; color: var(--foreground);
  }
  #tab-oauth:checked ~ .tab-panels .panel-oauth { display: block; }
  #tab-api:checked ~ .tab-panels .panel-api { display: block; }
  .divider {
    display: flex; align-items: center; gap: 0.75rem;
    margin: 1rem 0; color: #52525b; font-size: 0.75rem;
  }
  .divider::before, .divider::after {
    content: ''; flex: 1; height: 1px; background: #3f3f46;
  }
  .callback-notice {
    background: #1a1a2e;
    border: 1px solid #3f3f46;
    border-radius: var(--radius);
    padding: 0.75rem;
    margin-bottom: 1rem;
  }
  .callback-notice p {
    color: #a1a1aa;
    font-size: 0.8125rem;
    margin: 0 0 0.5rem;
  }
  .callback-url {
    display: block;
    color: var(--foreground);
    background: var(--muted);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.5rem 0.625rem;
    font-size: 0.75rem;
    word-break: break-all;
    user-select: all;
  }
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
    .two-col {
      grid-template-columns: 1fr;
    }

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
  .warden-badge a:hover { color: #52525b; }

  @media (max-width: 640px) {
    body { align-items: flex-start; padding: 1rem 0; }
    .container { padding: 1rem; }
    .tab-list { grid-template-columns: 1fr; }
  }
`

function serviceName(service: ServiceRow) {
  return service.displayName ?? service.service
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
  const totalCredentials = services.reduce((sum, service) => sum + (service.credentialCount ?? 0), 0)
  const activeServices = ranked.length

  return (
    <Layout title="Warden — Secure auth for AI agents">
      <section class="hero">
        <p class="eyebrow">Agent auth boundary</p>
        <h1>One URL between your agents and every API</h1>
        <p class="subtitle">
          Warden handles user auth, secure token handoff, and request proxying so agents can act without ever seeing provider secrets.
        </p>
        <div class="metrics">
          <span class="pill hot"><strong>{userCount}</strong> active orgs</span>
          <span class="pill warm"><strong>{activeServices}</strong> services in use</span>
          <span class="pill"><strong>{totalCredentials}</strong> stored credentials</span>
        </div>
        <div class="code-block copyable" onclick="navigator.clipboard.writeText(this.querySelector('span').textContent.trim()).then(()=>{this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),1800)})">
          <span class="mono">curl https://warden.run and help me connect to services</span>
          <span class="copy-icon" aria-hidden="true">
            <svg class="icon-copy" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
            <svg class="icon-check" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>
          </span>
          <span class="copy-hint">Paste this to your agent</span>
        </div>
      </section>

      <section class="section">
        <h2>Live service usage</h2>
        <p>Connected services by real credential usage.</p>
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
                  <span class="pill" style="gap: 0.3rem; display: inline-flex; align-items: center;">
                    <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
                      <circle cx="8" cy="5" r="3"/>
                      <path d="M2 14.5C2 11.5 4.7 9.5 8 9.5s6 2 6 5"/>
                    </svg>
                    {service.credentialCount ?? 0}
                  </span>
                </div>
                {service.description ? <div class="service-blurb">{service.description}</div> : null}
              </a>
            ))}
          </div>
        )}
      </section>

      <section class="section">
        <h2>What Warden does</h2>
        <div class="grid-3">
          <div class="card">
            <h3>Credential boundary</h3>
            <p>
              Users authenticate in the browser. Agents receive revocable Warden tokens, not raw provider API keys.
            </p>
          </div>
          <div class="card">
            <h3>Progressive discovery</h3>
            <p>
              Every service path doubles as docs and proxy: <span class="mono">/{'{hostname}'}</span> for discovery, <span class="mono">/{'{hostname}'}/...</span> for calls.
            </p>
          </div>
          <div class="card">
            <h3>Agent-safe error handling</h3>
            <p>
              Upstream credential failures are normalized to re-auth signals so agents stop retry loops and recover correctly.
            </p>
          </div>
        </div>
      </section>

      <section class="section">
        <h2>How auth handoff works</h2>
        <p>Five steps from first request to live API call.</p>
        <ol class="clean">
          <li><span class="mono">GET /{'{hostname}'}</span> returns discovery and an <span class="mono">auth_url</span>.</li>
          <li>Agent gives the user that URL.</li>
          <li>User authenticates in browser with OAuth or API key.</li>
          <li>Agent watches <span class="mono">/auth/status/{'{flow_id}'}</span> for completion.</li>
          <li>Agent proxies through Warden with <span class="mono">Authorization: Bearer wdn_...</span>.</li>
        </ol>
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
  const schemes = parseAuthSchemes(service.authSchemes)
  const hasOAuth = !!getOAuthScheme(schemes)
  const hasApiKey = !!getApiKeyScheme(schemes)
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
          <h1>{serviceName(service)}</h1>
          <p class="subtitle mono">{service.service}</p>
        </div>
      </section>

      <div class="two-col">
        <div class="col-left">
          <section class="col-section">
            <h3>About</h3>
            <p>{service.description ?? 'No service description yet. Warden can still handle auth and proxying.'}</p>
            <div class="status-row">
              <span class={`status-dot ${isActive ? 'active' : 'ready'}`}></span>
              <span>{statusText}</span>
            </div>
            <div class="metrics" style="margin-top: 0.6rem">
              <span class="pill"><strong>{schemes.length || 1}</strong> auth methods</span>
              <span class="pill"><strong>{service.apiType ?? 'unknown'}</strong> API type</span>
              <span class="pill"><strong>{totalPages}</strong> doc pages</span>
            </div>
            <div class="button-row">
              <a class="btn btn-secondary" href={docsHref}>Open docs</a>
              {service.docsUrl ? (
                <a class="btn btn-secondary" href={service.docsUrl} target="_blank" rel="noopener noreferrer">Upstream docs</a>
              ) : null}
            </div>
          </section>

          <section class="col-section">
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
              <p style="margin-top: 0.5rem">Discovered <strong>{coverage.total_resources}</strong> resources and <strong>{coverage.total_operations ?? 0}</strong> operations.</p>
            ) : null}
          </section>
        </div>

        <div class="col-right">
          <section class="col-section">
            <h3>Connect</h3>
            <div class="code-block copyable" onclick="navigator.clipboard.writeText(this.querySelector('span').textContent.trim()).then(()=>{this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),1800)})">
              <span class="mono">{`curl https://warden.run/${service.service} and help me use ${serviceName(service)}`}</span>
              <span class="copy-icon" aria-hidden="true">
                <svg class="icon-copy" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
                <svg class="icon-check" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>
              </span>
              <span class="copy-hint">Paste this to your agent</span>
            </div>
            {!hasCredentials ? (
              <div class="button-row" style="margin-top: 0.8rem">
                {hasOAuth ? (
                  <a href={`/auth/${service.service}/oauth`} class="btn btn-primary" style="width: 100%">Connect with OAuth</a>
                ) : null}
                {hasApiKey || schemes.length === 0 ? (
                  <a href={`/auth/${service.service}/api-key`} class="btn btn-secondary" style="width: 100%">Enter API Key</a>
                ) : null}
              </div>
            ) : (
              <div class="button-row" style="margin-top: 0.8rem">
                <a href={docsHref} class="btn btn-soft" style="width: 100%">Browse docs</a>
              </div>
            )}
          </section>

          {hasCredentials ? (
            <section class="col-section">
              <h3>Your credentials</h3>
              <ul class="credential-list">
                {(userCredentials ?? []).map(credential => (
                  <li>
                    <span class="mono">{credential.slug}</span>
                    <span style="color: var(--muted-foreground); font-size: 0.78rem">{formatTimeAgo(credential.updatedAt)}</span>
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          <section class="col-section">
            <div class="meta-line"><strong>{credentialCount}</strong> credentials stored</div>
            {service.docsUrl ? <div class="meta-line">Homepage: <a href={service.docsUrl} target="_blank" rel="noopener noreferrer">{service.docsUrl}</a></div> : null}
          </section>
        </div>
      </div>
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
  const oauthScheme = getOAuthScheme(parseAuthSchemes(service.authSchemes))
  const hasManagedOAuth = !!service.oauthClientId
  const hasOAuth = !!oauthScheme
  const defaultTab = hasOAuth ? 'oauth' : 'api'
  const name = service.displayName ?? service.service

  return (
    <Layout title={`Connect ${name} — Warden`}>
      <ServiceHeader service={service} />

      <div class="card">
        {/* Radio inputs must be direct children of .card so the ~ combinator can reach .tab-panels */}
        {hasOAuth && (
          <input
            class="tab-radio"
            id="tab-oauth"
            type="radio"
            name="auth-tab"
            checked={defaultTab === 'oauth'}
          />
        )}
        <input
          class="tab-radio"
          id="tab-api"
          type="radio"
          name="auth-tab"
          checked={defaultTab === 'api'}
        />

        <div class="tab-list">
          {hasOAuth && (
            <label class="tab-label" for="tab-oauth">OAuth</label>
          )}
          <label class="tab-label" for="tab-api">API Key</label>
        </div>

        <div class="tab-panels">
          {hasOAuth && (
            <div class="tab-panel panel-oauth">
              {hasManagedOAuth && (
                <>
                  <a
                    href={`/auth/${service.service}/oauth?flow_id=${flowId}&source=managed`}
                    class="btn btn-primary"
                    style="width: 100%"
                  >
                    Connect with OAuth
                  </a>
                  <div class="divider"><span>or use your own OAuth app</span></div>
                </>
              )}
              <div class="callback-notice">
                <p>Set this <strong>callback URL</strong> in your OAuth app:</p>
                <code class="callback-url">{callbackUrl}</code>
              </div>
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
                  <label for="scopes">Scopes (optional)</label>
                  <input
                    type="text"
                    id="scopes"
                    name="scopes"
                    placeholder={oauthScheme?.scopes ?? 'repo read:user'}
                    autocomplete="off"
                    spellcheck={false}
                  />
                </div>
                <button type="submit" class="btn btn-secondary" style="width: 100%">
                  Connect with your app
                </button>
              </form>
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
