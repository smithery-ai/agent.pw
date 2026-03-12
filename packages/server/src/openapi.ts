import { AuthScheme } from './auth-schemes'
import {
  CredProfileSchema,
  CredProfileDetailSchema,
  CredProfileListPageSchema,
  CreateCredProfileRequestSchema,
  ErrorSchema,
  OkSchema,
  OkWithSlugSchema,
} from './routes/cred-profiles'
import {
  CredentialSchema,
  CredentialErrorSchema,
  CredentialListPageSchema,
  CreateCredentialRequestSchema,
  DeleteCredentialQuerySchema,
} from './routes/credentials'
import {
  InspectTokenRequestSchema,
  InspectTokenResponseSchema,
  RestrictTokenRequestSchema,
  RestrictTokenResponseSchema,
  RevokeTokenRequestSchema,
  RevokeTokenResponseSchema,
} from './routes/tokens'

export const openAPIDocumentation = {
  openapi: '3.1.0',
  info: {
    title: 'agent.pw API',
    version: '1.0.0',
    description: 'API for managing credential profiles, credentials, tokens, and proxying authenticated requests.',
  },
  servers: [{ url: 'https://api.agent.pw' }],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http' as const,
        scheme: 'bearer',
        description: 'Biscuit bearer token',
      },
    },
  },
  security: [{ bearerAuth: [] }],
  tags: [
    { name: 'health', description: 'Health check' },
    { name: 'cred_profiles', description: 'Credential profile management' },
    { name: 'credentials', description: 'Credential storage and retrieval' },
    { name: 'tokens', description: 'Token management' },
    { name: 'proxy', description: 'Authenticated proxy' },
    { name: 'auth', description: 'Authentication endpoints' },
  ],
}

/** All Zod schemas with .meta({ id }) for injection into components.schemas. */
export const allSchemas = [
  AuthScheme,
  CredProfileSchema,
  CredProfileDetailSchema,
  CredProfileListPageSchema,
  CreateCredProfileRequestSchema,
  ErrorSchema,
  OkSchema,
  OkWithSlugSchema,
  CredentialSchema,
  CredentialErrorSchema,
  CredentialListPageSchema,
  CreateCredentialRequestSchema,
  DeleteCredentialQuerySchema,
  InspectTokenRequestSchema,
  InspectTokenResponseSchema,
  RestrictTokenRequestSchema,
  RestrictTokenResponseSchema,
  RevokeTokenRequestSchema,
  RevokeTokenResponseSchema,
]
