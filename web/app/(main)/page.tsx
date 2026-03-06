import { fetchCatalog, type CatalogService } from '@/lib/api'
import { ServiceCard } from '@/components/service/service-card'
import { CopyBlock } from './copy-block'

function serviceName(s: CatalogService) {
  return s.displayName ?? s.service
}

export default async function LandingPage() {
  const services = await fetchCatalog()
  const ranked = services
    .filter((s) => (s.credentialCount ?? 0) > 0 || !!s.oauthClientId)
    .sort(
      (a, b) =>
        (b.credentialCount ?? 0) - (a.credentialCount ?? 0) ||
        serviceName(a).localeCompare(serviceName(b)),
    )

  return (
    <main>
      {/* Hero */}
      <section className="py-6 pb-8 grid gap-5 animate-fade-up">
        <h1 className="m-0 text-[clamp(2.2rem,5.5vw,3.8rem)] leading-[0.95] tracking-[-0.025em] font-medium max-w-[16ch]">
          The vault between your agents and every API
        </h1>
        <p className="m-0 text-muted-foreground text-lg leading-relaxed max-w-[62ch]">
          Warden handles user auth, secure token handoff, and request proxying
          so agents can act without ever seeing provider secrets.
        </p>
        <CopyBlock text="curl https://agent.pw and help me connect to services" />
      </section>

      {/* Service Grid */}
      <section className="mt-6">
        <h2 className="m-0 mb-1 text-[clamp(1.3rem,2.1vw,1.8rem)] font-medium tracking-[-0.01em]">
          APIs
        </h2>
        {ranked.length === 0 ? (
          <div className="border border-border bg-card rounded-lg p-5">
            <h3 className="m-0 text-lg font-semibold">No services yet</h3>
            <p className="mt-1.5 text-muted-foreground">
              Hit <code className="font-mono">/{'{hostname}'}</code> once to
              auto-register a service.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mt-5">
            {ranked.map((s) => (
              <ServiceCard
                key={s.service}
                service={s.service}
                displayName={s.displayName}
                description={s.description}
                credentialCount={s.credentialCount}
              />
            ))}
          </div>
        )}
      </section>

      {/* Comparison */}
      <section className="mt-6">
        <h2 className="m-0 mb-1 text-[clamp(1.3rem,2.1vw,1.8rem)] font-medium tracking-[-0.01em]">
          Without vs with Warden
        </h2>
        <p className="m-0 text-muted-foreground">
          Same task, different integration surface.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-5">
          <div className="border border-border bg-card rounded-lg p-5">
            <span className="inline-flex items-center rounded-full px-2 py-0.5 border text-[0.68rem] font-bold tracking-[0.04em] uppercase text-destructive bg-destructive/10 border-destructive/20">
              Without Warden
            </span>
            <pre className="mt-3 mb-0 p-3.5 rounded-lg border border-[rgba(50,44,36,0.2)] bg-[#2a2520] text-[#e8e2d0] overflow-x-auto text-[0.77rem] leading-relaxed">
              <code>{`store raw keys in agent context:
LINEAR_API_KEY=lin_...
GITHUB_TOKEN=ghp_...

api.linear.app/graphql
api.github.com/repos

rotate + secure every key separately`}</code>
            </pre>
          </div>
          <div className="border border-border bg-card rounded-lg p-5">
            <span className="inline-flex items-center rounded-full px-2 py-0.5 border text-[0.68rem] font-bold tracking-[0.04em] uppercase text-success bg-success/10 border-success/30">
              With Warden
            </span>
            <pre className="mt-3 mb-0 p-3.5 rounded-lg border border-[rgba(50,44,36,0.2)] bg-[#2a2520] text-[#e8e2d0] overflow-x-auto text-[0.77rem] leading-relaxed">
              <code>{`GET /api.linear.app -> { auth_url, docs }
user authenticates in browser
GET /auth/status/{flow_id} -> token

POST /api.linear.app/graphql
  Authorization: Bearer apw_...
GET  /api.github.com/repos
  Authorization: Bearer apw_...`}</code>
            </pre>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="mt-6">
        <h2 className="m-0 mb-1 text-[clamp(1.3rem,2.1vw,1.8rem)] font-medium tracking-[-0.01em]">
          Features
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-5">
          <div className="border border-border bg-card rounded-lg p-5">
            <h3 className="m-0 text-base font-semibold">
              Secure credential proxy
            </h3>
            <p className="mt-1.5 text-sm text-muted-foreground leading-snug">
              Agents get revocable tokens — provider secrets never enter agent
              context. One URL pattern for auth, discovery, and proxying across
              every API.
            </p>
          </div>
          <div className="border border-border bg-card rounded-lg p-5">
            <h3 className="m-0 text-base font-semibold">Webhook events</h3>
            <p className="mt-1.5 text-sm text-muted-foreground leading-snug">
              Register callbacks through the proxy with a single header. Warden
              normalizes upstream signatures into one Ed25519 envelope agents can
              verify statelessly.
            </p>
          </div>
          <div className="border border-border bg-card rounded-lg p-5">
            <h3 className="m-0 text-base font-semibold">Service catalog</h3>
            <p className="mt-1.5 text-sm text-muted-foreground leading-snug">
              Hundreds of pre-configured services with auth schemes, webhook
              configs, and managed OAuth — ready to use.
            </p>
          </div>
        </div>
      </section>
    </main>
  )
}
