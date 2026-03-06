import { fetchService, firstHost, getApiUrl } from '@/lib/api'
import { ServiceIcon } from '@/components/service/service-icon'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { notFound } from 'next/navigation'
import Link from 'next/link'
import { ExternalLink, Key, Shield } from 'lucide-react'
import type { Metadata } from 'next'

interface Props {
  params: Promise<{ slug: string }>
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params
  const service = await fetchService(slug)
  if (!service) return { title: 'Service Not Found' }
  const name = service.displayName ?? service.slug
  return {
    title: `${name} — Warden`,
    description: service.description ?? `Connect to ${name} through Warden`,
  }
}

export default async function ServicePage({ params }: Props) {
  const { slug } = await params
  const service = await fetchService(slug)
  if (!service) notFound()

  const name = service.displayName ?? service.slug
  const apiUrl = getApiUrl()
  const hostname = firstHost(service.allowedHosts)

  const authSchemes = service.authSchemes
    ? JSON.parse(service.authSchemes)
    : null
  const hasOAuth = service.hasOAuth
  const hasApiKey = authSchemes?.some(
    (s: { type: string }) => s.type === 'apiKey' || s.type === 'http',
  )

  return (
    <main>
      {/* Service header */}
      <section className="mt-2 mb-6 flex items-center gap-4 animate-fade-up">
        <ServiceIcon hostname={hostname ?? service.slug} displayName={name} size="lg" />
        <div>
          <h1 className="text-[clamp(1.8rem,4vw,2.8rem)] font-medium leading-[0.95] tracking-[-0.025em]">
            {name}
          </h1>
          <p className="mt-1 text-sm text-muted-foreground font-mono">
            {service.slug}
          </p>
        </div>
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-[1fr_340px] gap-12 items-start">
        {/* Left column */}
        <div className="grid gap-0">
          {service.description && (
            <div className="pb-7 border-b border-border">
              <p className="text-base text-muted-foreground leading-relaxed">
                {service.description}
              </p>
            </div>
          )}

          <div className="py-7 border-b border-border">
            <h3 className="m-0 mb-2 text-base font-semibold">
              Authentication
            </h3>
            <div className="flex flex-wrap gap-2">
              {hasOAuth && (
                <Badge variant="success">OAuth</Badge>
              )}
              {hasApiKey && (
                <Badge variant="outline">API Key</Badge>
              )}
              {!hasOAuth && !hasApiKey && (
                <Badge variant="outline">Headers</Badge>
              )}
            </div>
          </div>

          <div className="py-7">
            <h3 className="m-0 mb-2 text-base font-semibold">Usage</h3>
            <p className="text-sm text-muted-foreground mb-3">
              Proxy requests through Warden with automatic credential injection:
            </p>
            <pre className="p-3.5 rounded-lg border border-[rgba(50,44,36,0.2)] bg-[#2a2520] text-[#e8e2d0] overflow-x-auto text-[0.77rem] leading-relaxed">
              <code>{`curl -H "Authorization: Bearer apw_..." \\
  ${apiUrl}/proxy/${service.slug}/${hostname ?? '{hostname}'}/...`}</code>
            </pre>
          </div>
        </div>

        {/* Right column */}
        <div className="grid gap-4">
          <div className="border border-border bg-card rounded-lg p-5">
            <h3 className="m-0 mb-3 text-base font-semibold">Connect</h3>
            <div className="grid gap-2">
              {hasOAuth && (
                <Button asChild className="w-full">
                  <Link href={`/connect?service=${encodeURIComponent(service.slug)}`}>
                    <Shield className="w-4 h-4" />
                    Connect with OAuth
                  </Link>
                </Button>
              )}
              <Button asChild variant="outline" className="w-full">
                <Link href={`/api-key?service=${encodeURIComponent(service.slug)}`}>
                  <Key className="w-4 h-4" />
                  Connect with API Key
                </Link>
              </Button>
            </div>
          </div>

          {service.docsUrl && (
            <Button asChild variant="ghost" className="w-full justify-start">
              <a
                href={service.docsUrl}
                target="_blank"
                rel="noopener noreferrer"
              >
                <ExternalLink className="w-4 h-4" />
                API Documentation
              </a>
            </Button>
          )}
        </div>
      </div>
    </main>
  )
}
