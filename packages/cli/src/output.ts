/** Returns true if stdout is a terminal (not piped). */
function isTTY() {
  return process.stdout.isTTY ?? false
}

/**
 * Output a single object. In non-TTY mode, prints JSON and returns true.
 * In TTY mode, returns false so the caller can print a human-readable format.
 */
export function output(data: unknown) {
  if (isTTY()) return false
  console.log(JSON.stringify(data))
  return true
}

/**
 * Output a list of objects. In non-TTY mode, prints NDJSON and returns true.
 * In TTY mode, returns false so the caller can print a human-readable format.
 */
export function outputList(items: unknown[]) {
  if (isTTY()) return false
  for (const item of items) {
    console.log(JSON.stringify(item))
  }
  return true
}

/**
 * Output a single paginated list page. In non-TTY mode, prints one JSON object
 * that preserves pagination metadata.
 */
export function outputListPage(page: {
  data: unknown[]
  hasMore: boolean
  nextCursor: string | null
}) {
  if (isTTY()) return false
  console.log(JSON.stringify(page))
  return true
}
