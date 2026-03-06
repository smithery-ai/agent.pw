import Link from 'next/link'
import { WardenLogo } from './logo'

export function Topbar() {
  return (
    <header className="sticky top-0 z-40 flex items-center justify-between gap-4 py-3.5 bg-background animate-fade-in">
      <Link
        href="/"
        className="inline-flex items-center gap-2.5 no-underline text-inherit transition-opacity hover:opacity-70"
      >
        <WardenLogo className="w-[30px] h-[34px] shrink-0 text-primary drop-shadow-[0_1px_3px_rgba(255,86,1,0.25)]" />
        <strong className="text-[1.65rem] font-medium tracking-[-0.015em]">
          Warden
        </strong>
      </Link>
    </header>
  )
}
