'use client'

import { useSearchParams } from 'next/navigation'
import { Suspense } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { ArrowLeft } from 'lucide-react'
import Link from 'next/link'

function ErrorContent() {
  const searchParams = useSearchParams()
  const message = searchParams.get('message') ?? 'An unknown error occurred'

  return (
    <main className="animate-fade-up">
      <section className="py-6">
        <p className="text-xs font-semibold text-destructive tracking-[0.06em] uppercase flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-sm bg-destructive shadow-[0_0_4px_rgba(123,23,7,0.3)]" />
          Warden Error
        </p>
        <h1 className="mt-2 text-[clamp(2rem,5vw,3rem)] font-medium leading-[0.95] tracking-[-0.025em]">
          Something failed
        </h1>
        <p className="mt-3 text-muted-foreground">
          The request could not be completed. Details are below.
        </p>
      </section>

      <Card>
        <CardContent className="p-6">
          <p className="text-destructive font-medium">{message}</p>
          <div className="mt-4">
            <Button asChild variant="outline">
              <Link href="/">
                <ArrowLeft className="w-4 h-4" />
                Back to registry
              </Link>
            </Button>
          </div>
        </CardContent>
      </Card>
    </main>
  )
}

export default function ErrorPage() {
  return (
    <Suspense>
      <ErrorContent />
    </Suspense>
  )
}
