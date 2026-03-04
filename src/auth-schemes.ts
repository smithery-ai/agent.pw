import { z } from 'zod'

const ApiKeyScheme = z.object({
  type: z.literal('apiKey'),
  in: z.enum(['header', 'query', 'cookie']).default('header'),
  name: z.string().default('Authorization'),
})

const HttpScheme = z.object({
  type: z.literal('http'),
  scheme: z.enum(['bearer', 'basic']),
})

const OAuth2Scheme = z.object({
  type: z.literal('oauth2'),
  authorizeUrl: z.string(),
  tokenUrl: z.string(),
  scopes: z.string().optional(),
})

export const AuthScheme = z.discriminatedUnion('type', [
  ApiKeyScheme,
  HttpScheme,
  OAuth2Scheme,
])
export type AuthScheme = z.infer<typeof AuthScheme>

export const DEFAULT_API_KEY_SCHEME: AuthScheme = { type: 'http', scheme: 'bearer' }

export function parseAuthSchemes(raw: string | null): AuthScheme[] {
  if (!raw) return []
  try {
    return z.array(AuthScheme).parse(JSON.parse(raw))
  } catch {
    return []
  }
}

export function getApiKeyScheme(schemes: AuthScheme[]) {
  return schemes.find(s => s.type === 'apiKey') ?? schemes.find(s => s.type === 'http')
}

export function getOAuthScheme(schemes: AuthScheme[]): Extract<AuthScheme, { type: 'oauth2' }> | undefined {
  return schemes.find((s): s is Extract<AuthScheme, { type: 'oauth2' }> => s.type === 'oauth2')
}
