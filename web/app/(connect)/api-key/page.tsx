'use client'

import { useSearchParams, useRouter } from 'next/navigation'
import { useState, Suspense } from 'react'
import { ServiceIcon } from '@/components/service/service-icon'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent } from '@/components/ui/card'
import { Loader2, Key } from 'lucide-react'

function ApiKeyForm() {
  const searchParams = useSearchParams()
  const router = useRouter()
  const service = searchParams.get('service') ?? ''
  const flowId = searchParams.get('flow_id') ?? ''
  const [apiKey, setApiKey] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const apiUrl =
    process.env.NEXT_PUBLIC_WARDEN_API_URL ?? 'https://api.agent.pw'

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!apiKey.trim()) return

    setLoading(true)
    setError(null)

    try {
      const res = await fetch(`${apiUrl}/auth/${service}/api-key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          api_key: apiKey,
          flow_id: flowId || undefined,
        }),
      })

      const data = await res.json()

      if (!res.ok) {
        setError(data.error ?? 'Failed to connect')
        return
      }

      router.push(
        `/success?token=${encodeURIComponent(data.token)}&service=${encodeURIComponent(service)}`,
      )
    } catch {
      setError('Network error. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="animate-fade-up">
      <section className="mt-2 mb-6 flex items-center gap-4">
        <ServiceIcon hostname={service} size="lg" />
        <div>
          <p className="text-xs font-semibold text-primary tracking-[0.06em] uppercase flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-sm bg-primary shadow-[0_0_6px_rgba(255,86,1,0.4)]" />
            Credential Setup
          </p>
          <h1 className="text-2xl font-medium tracking-[-0.015em]">
            Connect {service}
          </h1>
          {flowId && (
            <p className="mt-0.5 text-xs text-muted-foreground font-mono">
              flow_id={flowId}
            </p>
          )}
        </div>
      </section>

      <div className="grid gap-4">
        <Card>
          <CardContent className="p-6">
            <h3 className="m-0 mb-1 text-base font-semibold">Enter API Key</h3>
            <p className="text-sm text-muted-foreground mb-4">
              Warden encrypts this value and injects it at proxy time.
            </p>
            <form onSubmit={handleSubmit} className="grid gap-4">
              <div className="grid gap-2">
                <Label htmlFor="api_key">API Key</Label>
                <Input
                  id="api_key"
                  type="password"
                  placeholder={`Paste your ${service} key`}
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  required
                  autoComplete="off"
                  spellCheck={false}
                />
              </div>
              {error && (
                <p className="text-sm text-destructive font-medium">{error}</p>
              )}
              <Button type="submit" disabled={loading} className="w-full">
                {loading ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Key className="w-4 h-4" />
                )}
                {loading ? 'Connecting...' : 'Connect'}
              </Button>
            </form>
          </CardContent>
        </Card>

        {flowId && (
          <Card>
            <CardContent className="p-6">
              <h3 className="m-0 mb-1 text-base font-semibold">
                Agent Polling
              </h3>
              <p className="text-sm text-muted-foreground mb-3">
                After the user submits this form, agents poll for completion:
              </p>
              <pre className="p-3 rounded-lg border border-[rgba(50,44,36,0.2)] bg-[#2a2520] text-[#e8e2d0] overflow-x-auto text-[0.77rem] leading-relaxed">
                <code>{`GET /auth/status/${flowId}`}</code>
              </pre>
              <p className="text-sm text-muted-foreground mt-2">
                On completion, the response includes a revocable Warden token.
              </p>
            </CardContent>
          </Card>
        )}
      </div>
    </main>
  )
}

export default function ApiKeyPage() {
  return (
    <Suspense>
      <ApiKeyForm />
    </Suspense>
  )
}
