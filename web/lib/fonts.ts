import localFont from 'next/font/local'

export const pantheon = localFont({
  src: [
    {
      path: '../public/fonts/gt-pantheon-micro-regular.woff2',
      weight: '400',
    },
    {
      path: '../public/fonts/gt-pantheon-micro-medium.woff2',
      weight: '500',
    },
  ],
  display: 'swap',
  variable: '--font-sans',
  fallback: [
    'ui-sans-serif',
    'system-ui',
    '-apple-system',
    'Segoe UI',
    'Roboto',
    'Arial',
    'sans-serif',
  ],
})
