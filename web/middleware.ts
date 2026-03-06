import { NextResponse, type NextRequest } from 'next/server'

const AGENT_USER_AGENTS = [
  'curl/',
  'wget/',
  'httpie/',
  'python-requests/',
  'node-fetch/',
  'undici/',
  'axios/',
  'got/',
]

function isAgentRequest(req: NextRequest) {
  const accept = req.headers.get('accept') ?? ''
  if (accept.includes('text/markdown') || accept.includes('text/plain')) {
    return true
  }
  if (accept.includes('text/html')) {
    return false
  }
  const ua = (req.headers.get('user-agent') ?? '').toLowerCase()
  return AGENT_USER_AGENTS.some((agent) => ua.includes(agent))
}

export function middleware(req: NextRequest) {
  if (!isAgentRequest(req)) return NextResponse.next()

  const { pathname } = req.nextUrl

  // Rewrite agent requests to markdown route handlers
  if (pathname === '/') {
    return NextResponse.rewrite(new URL('/api/markdown', req.url))
  }

  const serviceMatch = pathname.match(/^\/service\/(.+)$/)
  if (serviceMatch) {
    return NextResponse.rewrite(
      new URL(`/api/markdown/service/${serviceMatch[1]}`, req.url),
    )
  }

  return NextResponse.next()
}

export const config = {
  matcher: ['/', '/service/:path*'],
}
