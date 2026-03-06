import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { pantheon } from '@/lib/fonts'
import { ThemeProvider } from '@/components/theme-provider'
import './globals.css'

export const metadata: Metadata = {
  title: {
    default: 'Warden — Secure auth for AI agents',
    template: '%s — Warden',
  },
  description:
    'Credential vault and API proxy for agents. Keeps secrets out of your prompts.',
}

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){try{var t=localStorage.getItem('warden-theme');var d=t==='dark'||(t!=='light'&&matchMedia('(prefers-color-scheme:dark)').matches);if(d)document.documentElement.classList.add('dark')}catch(e){}})()`,
          }}
        />
      </head>
      <body
        className={`${pantheon.variable} ${pantheon.className} min-h-screen`}
      >
        <ThemeProvider>{children}</ThemeProvider>
      </body>
    </html>
  )
}
