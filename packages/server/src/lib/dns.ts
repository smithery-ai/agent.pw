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
