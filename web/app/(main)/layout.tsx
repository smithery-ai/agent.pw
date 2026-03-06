import type { ReactNode } from 'react'
import { Topbar } from '@/components/brand/topbar'
import { Footer } from '@/components/brand/footer'

export default function MainLayout({ children }: { children: ReactNode }) {
  return (
    <div className="gradient-bg noise-bg">
      <div className="relative z-[2] w-[min(1140px,100%-2.5rem)] mx-auto py-4 pb-12">
        <Topbar />
        {children}
        <Footer />
      </div>
    </div>
  )
}
