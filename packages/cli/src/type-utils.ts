export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export class HttpStatusError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'HttpStatusError'
    this.status = status
  }
}

export function getErrorStatus(error: unknown): number | undefined {
  if (!isRecord(error)) {
    return undefined
  }

  return typeof error.status === 'number' ? error.status : undefined
}
