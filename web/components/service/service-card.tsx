import Link from 'next/link'
import { ServiceIcon } from './service-icon'
import { Users } from 'lucide-react'

interface ServiceCardProps {
  service: string
  displayName: string | null
  description: string | null
  credentialCount: number
}

export function ServiceCard({
  service,
  displayName,
  description,
  credentialCount,
}: ServiceCardProps) {
  const name = displayName ?? service

  return (
    <Link
      href={`/service/${encodeURIComponent(service)}`}
      className="block border border-border bg-card rounded-lg p-4 shadow-[0_1px_3px_rgba(35,35,35,0.04)] no-underline text-inherit transition-all hover:border-primary/30 hover:shadow-[0_4px_20px_rgba(255,86,1,0.07),0_1px_3px_rgba(35,35,35,0.06)] hover:-translate-y-0.5"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <ServiceIcon hostname={service} displayName={displayName} />
          <div className="min-w-0">
            <h3 className="m-0 text-base font-semibold tracking-[-0.005em]">
              {name}
            </h3>
            <div className="mt-1 text-xs text-muted-foreground font-mono break-all">
              {service}
            </div>
          </div>
        </div>
        {credentialCount > 0 && (
          <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 border border-border bg-card text-xs">
            <Users className="w-3.5 h-3.5" />
            {credentialCount}
          </span>
        )}
      </div>
      {description && (
        <p className="mt-2 text-sm text-muted-foreground leading-snug line-clamp-2 break-all">
          {description}
        </p>
      )}
    </Link>
  )
}
