import type { ReactNode } from 'react'
import { Topbar } from '@/components/brand/topbar'

export default function ConnectLayout({ children }: { children: ReactNode }) {
  return (
    <div className="gradient-bg noise-bg min-h-screen">
      <div className="relative z-[2] w-[min(560px,100%-2.5rem)] mx-auto py-4 pb-12">
        <Topbar />
        {children}
      </div>
    </div>
  )
}
