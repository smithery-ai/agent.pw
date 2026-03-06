'use client'

import { useSearchParams } from 'next/navigation'
import { useState, Suspense } from 'react'
import { ServiceIcon } from '@/components/service/service-icon'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Copy, Check, ArrowLeft } from 'lucide-react'
import Link from 'next/link'

function SuccessContent() {
  const searchParams = useSearchParams()
  const token = searchParams.get('token') ?? ''
  const service = searchParams.get('service') ?? ''
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    navigator.clipboard.writeText(token).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    })
  }

  return (
    <main className="animate-fade-up">
      <section className="mt-2 mb-6 flex items-center gap-4">
        <ServiceIcon hostname={service} size="lg" />
        <div>
          <p className="text-xs font-semibold text-primary tracking-[0.06em] uppercase flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-sm bg-success shadow-[0_0_4px_rgba(78,138,55,0.3)]" />
            Connection Complete
          </p>
          <h1 className="text-2xl font-medium tracking-[-0.015em]">
            {service} connected
          </h1>
          <p className="mt-0.5 text-sm text-muted-foreground">
            Share this token with your agent. It can be revoked at any time.
          </p>
        </div>
      </section>

      <Card>
        <CardContent className="p-6">
          <Label className="text-sm font-medium">Warden token</Label>
          <div className="mt-2 border border-border rounded-lg bg-background p-3 text-xs font-mono leading-relaxed break-all">
            {token}
          </div>
          <div className="flex flex-wrap gap-2 mt-4">
            <Button onClick={handleCopy}>
              {copied ? (
                <Check className="w-4 h-4" />
              ) : (
                <Copy className="w-4 h-4" />
              )}
              {copied ? 'Copied' : 'Copy token'}
            </Button>
            <Button asChild variant="outline">
              <Link href={`/service/${encodeURIComponent(service)}`}>
                <ArrowLeft className="w-4 h-4" />
                Return to service
              </Link>
            </Button>
          </div>
        </CardContent>
      </Card>
    </main>
  )
}

function Label({
  className,
  children,
}: {
  className?: string
  children: React.ReactNode
}) {
  return <span className={className}>{children}</span>
}

export default function SuccessPage() {
  return (
    <Suspense>
      <SuccessContent />
    </Suspense>
  )
}
