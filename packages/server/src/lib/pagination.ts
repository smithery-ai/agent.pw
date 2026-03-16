import { z } from 'zod'
import { lastItem } from './utils'

export const MAX_PAGE_SIZE = 100
export const DEFAULT_PAGE_SIZE = MAX_PAGE_SIZE

export const PaginationQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).meta({
    description: `Maximum number of items to return (1-${MAX_PAGE_SIZE})`,
    example: DEFAULT_PAGE_SIZE,
  }),
  cursor: z.string().optional().meta({
    description: 'Opaque cursor returned by a previous list response',
    example: 'eyJzbHVnIjoiL2dpdGh1YiJ9',
  }),
})

export interface ListPage<T> {
  data: T[]
  hasMore: boolean
  nextCursor: string | null
}

export class InvalidPaginationCursorError extends Error {
  constructor(message = 'Invalid pagination cursor') {
    super(message)
    this.name = 'InvalidPaginationCursorError'
  }
}

function toBase64Url(value: string) {
  return btoa(value)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

function fromBase64Url(value: string) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const paddingLength = normalized.length % 4 === 0 ? 0 : 4 - (normalized.length % 4)
  return atob(`${normalized}${'='.repeat(paddingLength)}`)
}

export function encodePageCursor<T>(value: T) {
  return toBase64Url(JSON.stringify(value))
}

export function decodePageCursor<_T>(cursor: string) {
  try {
    return JSON.parse(fromBase64Url(cursor))
  } catch {
    throw new InvalidPaginationCursorError()
  }
}

export function decodePageCursorWithSchema<T extends z.ZodTypeAny>(cursor: string, schema: T): z.infer<T> {
  const parsed = schema.safeParse(decodePageCursor<unknown>(cursor))
  if (!parsed.success) {
    throw new InvalidPaginationCursorError()
  }
  return parsed.data
}

interface PaginateItemsOptions<T, Cursor> {
  items: T[]
  limit: number
  cursor?: string | null
  compareToCursor: (item: T, cursor: Cursor) => number
  toCursor: (item: T) => Cursor
}

interface PaginateSliceOptions<T, Cursor> {
  items: T[]
  limit: number
  toCursor: (item: T) => Cursor
}

export function paginateSlice<T, Cursor>({
  items,
  limit,
  toCursor,
}: PaginateSliceOptions<T, Cursor>): ListPage<T> {
  const data = items.slice(0, limit)
  const hasMore = items.length > limit

  return {
    data,
    hasMore,
    nextCursor: hasMore
      ? (() => {
          const item = lastItem(data)
          return item ? encodePageCursor(toCursor(item)) : null
        })()
      : null,
  }
}

export function paginateItems<T, Cursor>({
  items,
  limit,
  cursor,
  compareToCursor,
  toCursor,
}: PaginateItemsOptions<T, Cursor>): ListPage<T> {
  const cursorValue = cursor ? decodePageCursor<Cursor>(cursor) : null
  const remainingItems = cursorValue
    ? items.filter(item => compareToCursor(item, cursorValue) > 0)
    : items

  return paginateSlice({
    items: remainingItems,
    limit,
    toCursor,
  })
}

export function buildListPageSchema<Item extends z.ZodType>(itemSchema: Item, id: string) {
  return z.object({
    data: z.array(itemSchema),
    hasMore: z.boolean().meta({ description: 'Whether more items remain after this page' }),
    nextCursor: z.string().nullable().meta({ description: 'Cursor to request the next page' }),
  }).meta({ id })
}
