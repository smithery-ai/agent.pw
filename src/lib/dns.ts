const REACHABILITY_TIMEOUT = 3000

/** Check whether an error thrown by `fetch()` is a DNS resolution failure. */
export function isDnsError(error: unknown): boolean {
  if (!(error instanceof Error)) return false
  const msg = error.message.toLowerCase()
  return (
    msg.includes('getaddrinfo') ||
    msg.includes('enotfound') ||
    msg.includes('name resolution') ||
    msg.includes('could not resolve') ||
    // CF Workers: TypeError with generic "fetch failed" when DNS fails
    (error instanceof TypeError && msg.includes('fetch failed'))
  )
}

/**
 * Quick reachability check — a HEAD request with a short timeout.
 * Any HTTP response (even 4xx/5xx) means the domain resolves.
 * Only DNS failures indicate the domain does not exist.
 */
export async function checkHostReachable(hostname: string) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), REACHABILITY_TIMEOUT)
  try {
    await fetch(`https://${hostname}/`, {
      method: 'HEAD',
      signal: controller.signal,
      redirect: 'manual',
    })
    return { reachable: true as const }
  } catch (error) {
    if (isDnsError(error)) {
      return { reachable: false as const, reason: 'dns' as const }
    }
    if (error instanceof DOMException && error.name === 'AbortError') {
      return { reachable: false as const, reason: 'timeout' as const }
    }
    return { reachable: false as const, reason: 'error' as const }
  } finally {
    clearTimeout(timer)
  }
}
