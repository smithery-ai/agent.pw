import { customType } from 'drizzle-orm/pg-core'

export const bytea = customType<{ data: Buffer }>({
  dataType() {
    return 'bytea'
  },
})

export const jsonb = <T>() =>
  customType<{ data: T; driverValue: string }>({
    dataType() {
      return 'jsonb'
    },
    toDriver(value: T) {
      return JSON.stringify(value)
    },
    fromDriver(value: unknown) {
      if (typeof value !== 'string') return value as T
      try {
        return JSON.parse(value) as T
      } catch {
        // Older rows may contain a primitive string payload rather than JSON text.
        return value as T
      }
    },
  })

export const ltree = customType<{ data: string; driverValue: string }>({
  dataType() {
    return 'text'
  },
})
