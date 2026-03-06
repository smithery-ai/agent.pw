import { fetchService, firstHost, getApiUrl } from '@/lib/api'
import { ServiceIcon } from '@/components/service/service-icon'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { notFound, redirect } from 'next/navigation'
import Link from 'next/link'
import { ExternalLink, Shield, Key } from 'lucide-react'
import type { Metadata } from 'next'

interface Props {
  searchParams: Promise<{ service?: string; flow_id?: string }>
}

export async function generateMetadata({ searchParams }: Props): Promise<Metadata> {
  const { service: slug } = await searchParams
  if (!slug) return { title: 'Connect' }
  const service = await fetchService(slug)
  const name = service?.displayName ?? slug
  return { title: `Connect ${name}` }
}

export default async function ConnectPage({ searchParams }: Props) {
  const { service: slug, flow_id: flowId } = await searchParams

  if (!slug) redirect('/')

  const service = await fetchService(slug)
  if (!service) notFound()

  const name = service.displayName ?? service.slug
  const apiUrl = getApiUrl()
  const hostname = firstHost(service.allowedHosts)
  const hasOAuth = service.hasOAuth

  return (
    <main className="animate-fade-up">
      {/* Service header */}
      <section className="mt-2 mb-6 flex items-center gap-4">
        <ServiceIcon hostname={hostname ?? service.slug} displayName={name} size="lg" />
        <div>
          <h1 className="text-2xl font-medium tracking-[-0.015em]">
            Connect {name}
          </h1>
          <p className="mt-0.5 text-sm text-muted-foreground font-mono">
            {service.slug}
          </p>
        </div>
      </section>

      <Card>
        <CardContent className="p-6 space-y-4">
          {/* OAuth option */}
          {hasOAuth && (
            <>
              <Button asChild className="w-full" size="lg">
                <a
                  href={`${apiUrl}/auth/${service.slug}/oauth${flowId ? `?flow_id=${flowId}&source=managed` : '?source=managed'}`}
                >
                  <Shield className="w-4 h-4" />
                  Connect with OAuth
                </a>
              </Button>

              {/* BYO OAuth section */}
              <div className="flex items-center gap-3 text-muted-foreground text-xs">
                <div className="flex-1 h-px bg-border" />
                <span>or use your own OAuth app</span>
                <div className="flex-1 h-px bg-border" />
              </div>

              <div className="bg-primary/5 border border-primary/15 rounded-lg p-3 text-sm">
                <p className="text-muted-foreground text-[0.8125rem] mb-2">
                  Set this <strong>callback URL</strong> in your OAuth app:
                </p>
                <code className="block bg-muted border border-border rounded px-2.5 py-2 text-xs break-all select-all">
                  {apiUrl}/auth/{service.slug}/oauth/callback
                </code>
              </div>
            </>
          )}

          {/* API Key option */}
          <Button asChild variant={hasOAuth ? 'outline' : 'default'} className="w-full" size="lg">
            <Link
              href={`/api-key?service=${encodeURIComponent(service.slug)}${flowId ? `&flow_id=${flowId}` : ''}`}
            >
              <Key className="w-4 h-4" />
              Connect with API Key
            </Link>
          </Button>

          {service.docsUrl && (
            <p className="text-sm text-muted-foreground">
              Need a key?{' '}
              <a
                href={service.docsUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-foreground underline underline-offset-2 inline-flex items-center gap-1"
              >
                Get one from {name}
                <ExternalLink className="w-3 h-3" />
              </a>
            </p>
          )}
        </CardContent>
      </Card>
    </main>
  )
}
