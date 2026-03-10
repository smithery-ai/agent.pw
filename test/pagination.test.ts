import { describe, expect, it } from 'vitest'
import { z } from 'zod'
import {
  buildListPageSchema,
  decodePageCursor,
  encodePageCursor,
  InvalidPaginationCursorError,
  paginateItems,
} from '@agent.pw/server/pagination'

describe('pagination helpers', () => {
  it('encodes and decodes opaque cursors', () => {
    const encoded = encodePageCursor({ slug: '/github' })

    expect(encoded).not.toContain('{')
    expect(decodePageCursor<{ slug: string }>(encoded)).toEqual({ slug: '/github' })
  })

  it('rejects malformed cursors', () => {
    expect(() => decodePageCursor('not-a-valid-cursor')).toThrow(InvalidPaginationCursorError)
  })

  it('slices items and emits a next cursor when more remain', () => {
    const page = paginateItems({
      items: [
        { slug: '/a' },
        { slug: '/b' },
        { slug: '/c' },
      ],
      limit: 2,
      compareToCursor: (item, cursor: { slug: string }) => item.slug.localeCompare(cursor.slug),
      toCursor: item => ({ slug: item.slug }),
    })

    expect(page).toEqual({
      data: [{ slug: '/a' }, { slug: '/b' }],
      hasMore: true,
      nextCursor: encodePageCursor({ slug: '/b' }),
    })
  })

  it('continues from a prior cursor and returns a terminal page', () => {
    const page = paginateItems({
      items: [
        { createdAt: '2026-03-03T00:00:00.000Z', path: '/c', host: 'api.example.com' },
        { createdAt: '2026-03-02T00:00:00.000Z', path: '/b', host: 'api.example.com' },
        { createdAt: '2026-03-01T00:00:00.000Z', path: '/a', host: 'api.example.com' },
      ],
      limit: 2,
      cursor: encodePageCursor({
        createdAt: '2026-03-03T00:00:00.000Z',
        path: '/c',
        host: 'api.example.com',
      }),
      compareToCursor: (item, cursor: { createdAt: string; path: string; host: string }) =>
        new Date(cursor.createdAt).getTime() - new Date(item.createdAt).getTime()
          || item.path.localeCompare(cursor.path)
          || item.host.localeCompare(cursor.host),
      toCursor: item => ({
        createdAt: item.createdAt,
        path: item.path,
        host: item.host,
      }),
    })

    expect(page).toEqual({
      data: [
        { createdAt: '2026-03-02T00:00:00.000Z', path: '/b', host: 'api.example.com' },
        { createdAt: '2026-03-01T00:00:00.000Z', path: '/a', host: 'api.example.com' },
      ],
      hasMore: false,
      nextCursor: null,
    })
  })

  it('builds reusable list page schemas', () => {
    const schema = buildListPageSchema(z.object({ slug: z.string() }), 'TestListPage')

    expect(schema.parse({
      data: [{ slug: '/github' }],
      hasMore: false,
      nextCursor: null,
    })).toEqual({
      data: [{ slug: '/github' }],
      hasMore: false,
      nextCursor: null,
    })
  })
})
