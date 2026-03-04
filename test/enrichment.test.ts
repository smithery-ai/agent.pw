import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createTestDb, type TestDb } from './setup'
import { upsertDocPage, getDocPage } from '../src/db/queries'

// Mock @ai-sdk/anthropic — returns a factory that produces a fake model
vi.mock('@ai-sdk/anthropic', () => ({
  createAnthropic: vi.fn(() => (modelId: string) => ({ modelId })),
}))

// Mock ai — generateText calls write_doc_page tool to simulate enrichment
vi.mock('ai', async (importOriginal) => {
  const actual = await importOriginal<typeof import('ai')>()
  return {
    ...actual,
    generateText: vi.fn(async (opts: any) => {
      // Extract page path from the prompt
      const match = opts.prompt?.match(/Page: (.+)\n/)
      const pagePath = match?.[1] ?? 'sitemap/unknown.json'

      // Simulate the model calling write_doc_page
      const writeTool = opts.tools?.write_doc_page
      if (writeTool?.execute) {
        await writeTool.execute(
          {
            path: pagePath,
            content: {
              level: 2,
              resource: 'test-resource',
              description: 'AI-enriched description for testing',
              operations: [
                { method: 'GET', path: '/test', summary: 'Test endpoint', slug: 'get-test' },
              ],
            },
          },
          { abortSignal: new AbortController().signal, toolCallId: 'mock-call-1' },
        )
      }

      // Call onStepFinish if provided (exercises logging code path)
      opts.onStepFinish?.({
        toolCalls: [{ toolName: 'write_doc_page', args: {} }],
      })

      return { steps: [{}], text: 'Done' }
    }),
  }
})

import { enrichPage, enrichPages } from '../src/discovery/enrichment'
import { generateText } from 'ai'
import { createAnthropic } from '@ai-sdk/anthropic'

describe('Enrichment', () => {
  let db: TestDb

  beforeEach(async () => {
    db = await createTestDb()
    vi.clearAllMocks()
  })

  function makeCtx(overrides?: Partial<Parameters<typeof enrichPage>[0]>) {
    return {
      db,
      hostname: 'api.example.com',
      service: {
        service: 'api.example.com',
        baseUrl: 'https://api.example.com',
        displayName: 'Example',
        description: 'Test API',
        authSchemes: JSON.stringify([{ type: 'http', scheme: 'bearer' }]),
        oauthClientId: null,
        encryptedOauthClientSecret: null,
        apiType: 'rest',
        docsUrl: 'https://docs.example.com',
        preview: null,
        authConfig: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      anthropicApiKey: 'sk-test-key',
      baseUrl: 'http://localhost:3000',
      ...overrides,
    }
  }

  it('skips enrichment when no API key is configured', async () => {
    await upsertDocPage(db, 'api.example.com', 'sitemap/test.json', '{}', 'skeleton')
    await enrichPage(makeCtx({ anthropicApiKey: undefined }), 'sitemap/test.json')

    expect(generateText).not.toHaveBeenCalled()
    const page = await getDocPage(db, 'api.example.com', 'sitemap/test.json')
    expect(page?.status).toBe('skeleton')
  })

  it('skips enrichment when page does not exist', async () => {
    await enrichPage(makeCtx(), 'sitemap/nonexistent.json')
    expect(generateText).not.toHaveBeenCalled()
  })

  it('enriches a skeleton page via generateText tool call', async () => {
    const skeleton = JSON.stringify({ level: 2, resource: 'test-resource', description: '', operations: [] })
    await upsertDocPage(db, 'api.example.com', 'sitemap/test.json', skeleton, 'skeleton')

    await enrichPage(makeCtx(), 'sitemap/test.json')

    // Verify generateText was called with correct config
    expect(generateText).toHaveBeenCalledOnce()
    const callArgs = (generateText as any).mock.calls[0][0]
    expect(callArgs.system).toContain('Example')
    expect(callArgs.system).toContain('https://api.example.com')
    expect(callArgs.prompt).toContain('sitemap/test.json')
    expect(callArgs.tools.fetch_upstream).toBeUndefined()
    expect(callArgs.tools.write_doc_page).toBeDefined()

    // Verify createAnthropic was called with the API key
    expect(createAnthropic).toHaveBeenCalledWith(
      expect.objectContaining({ apiKey: 'sk-test-key' }),
    )

    // Verify the page was enriched in the database
    const page = await getDocPage(db, 'api.example.com', 'sitemap/test.json')
    expect(page).toBeTruthy()
    expect(page?.status).toBe('enriched')
    const content = JSON.parse(page!.content!)
    expect(content.description).toBe('AI-enriched description for testing')
    expect(content.operations).toHaveLength(1)
  })

  it('passes anthropicBaseUrl when configured', async () => {
    await upsertDocPage(db, 'api.example.com', 'sitemap/test.json', '{}', 'skeleton')

    await enrichPage(
      makeCtx({ anthropicBaseUrl: 'https://gateway.ai.cloudflare.com/v1/acct/gw/anthropic' }),
      'sitemap/test.json',
    )

    expect(createAnthropic).toHaveBeenCalledWith(
      expect.objectContaining({
        apiKey: 'sk-test-key',
        baseURL: 'https://gateway.ai.cloudflare.com/v1/acct/gw/anthropic',
      }),
    )
  })

  it('does not inject other pages as context', async () => {
    await upsertDocPage(db, 'api.example.com', 'sitemap/index.json', '{"level":0}', 'enriched')
    await upsertDocPage(db, 'api.example.com', 'sitemap/resources.json', '{"level":1}', 'enriched')
    await upsertDocPage(db, 'api.example.com', 'sitemap/target.json', '{"level":2}', 'skeleton')

    await enrichPage(makeCtx(), 'sitemap/target.json')

    const callArgs = (generateText as any).mock.calls[0][0]
    expect(callArgs.prompt).not.toContain('sitemap/index.json')
    expect(callArgs.prompt).not.toContain('sitemap/resources.json')
  })

  it('includes docsUrl hint in prompt when available', async () => {
    await upsertDocPage(db, 'api.example.com', 'sitemap/test.json', '{}', 'skeleton')
    await enrichPage(makeCtx(), 'sitemap/test.json')

    const callArgs = (generateText as any).mock.calls[0][0]
    expect(callArgs.prompt).toContain('https://docs.example.com')
  })

  it('enrichPages processes multiple pages and handles errors', async () => {
    await upsertDocPage(db, 'api.example.com', 'sitemap/a.json', '{}', 'skeleton')
    await upsertDocPage(db, 'api.example.com', 'sitemap/b.json', '{}', 'skeleton')

    const ctx = makeCtx()
    await enrichPages(ctx, ['sitemap/a.json', 'sitemap/b.json'])

    expect(generateText).toHaveBeenCalledTimes(2)

    const pageA = await getDocPage(db, 'api.example.com', 'sitemap/a.json')
    const pageB = await getDocPage(db, 'api.example.com', 'sitemap/b.json')
    expect(pageA?.status).toBe('enriched')
    expect(pageB?.status).toBe('enriched')
  })

  it('enrichPages continues after individual page failure', async () => {
    await upsertDocPage(db, 'api.example.com', 'sitemap/a.json', '{}', 'skeleton')
    await upsertDocPage(db, 'api.example.com', 'sitemap/b.json', '{}', 'skeleton')

    // Make generateText fail on first call, succeed on second
    const mockGenerateText = generateText as ReturnType<typeof vi.fn>
    mockGenerateText
      .mockRejectedValueOnce(new Error('API error'))
      .mockImplementationOnce(async (opts: any) => {
        const writeTool = opts.tools?.write_doc_page
        if (writeTool?.execute) {
          const match = opts.prompt?.match(/Page: (.+)\n/)
          await writeTool.execute(
            { path: match?.[1] ?? 'sitemap/b.json', content: { enriched: true } },
            { abortSignal: new AbortController().signal, toolCallId: 'mock-2' },
          )
        }
        return { steps: [{}], text: 'Done' }
      })

    await enrichPages(makeCtx(), ['sitemap/a.json', 'sitemap/b.json'])

    // First page should remain skeleton (enrichment failed)
    const pageA = await getDocPage(db, 'api.example.com', 'sitemap/a.json')
    expect(pageA?.status).toBe('skeleton')

    // Second page should be enriched (enrichment succeeded)
    const pageB = await getDocPage(db, 'api.example.com', 'sitemap/b.json')
    expect(pageB?.status).toBe('enriched')
  })
})
