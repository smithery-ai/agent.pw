'use client'

import { useState } from 'react'
import { inferServiceIconPreview } from '@/lib/service-preview'
import { cn } from '@/lib/utils'

interface ServiceIconProps {
  hostname: string
  displayName?: string | null
  size?: 'sm' | 'md' | 'lg'
  className?: string
}

const sizes = {
  sm: 'w-10 h-10 rounded-[10px] text-xs',
  md: 'w-[52px] h-[52px] rounded-[13px] text-sm',
  lg: 'w-16 h-16 rounded-2xl text-base',
}

const imgSizes = {
  sm: 'w-5 h-5',
  md: 'w-7 h-7',
  lg: 'w-9 h-9',
}

export function ServiceIcon({
  hostname,
  displayName,
  size = 'md',
  className,
}: ServiceIconProps) {
  const icon = inferServiceIconPreview(hostname, displayName ?? undefined)
  const [imgError, setImgError] = useState(false)

  return (
    <div
      className={cn(
        'inline-flex items-center justify-center relative overflow-hidden shrink-0 font-semibold tracking-[0.02em] bg-muted border border-border transition-shadow',
        sizes[size],
        className,
      )}
      title={hostname}
    >
      {icon.url && !imgError ? (
        <img
          src={icon.url}
          alt={`${displayName ?? hostname} icon`}
          loading="lazy"
          className={cn('object-contain rounded-[6px]', imgSizes[size])}
          onError={() => setImgError(true)}
        />
      ) : (
        <span className="inline-flex items-center justify-center leading-none">
          {icon.fallback}
        </span>
      )}
    </div>
  )
}
