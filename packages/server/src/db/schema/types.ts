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
      return (typeof value === 'string' ? JSON.parse(value) : value) as T
    },
  })
