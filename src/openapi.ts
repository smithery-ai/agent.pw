import { AuthScheme } from './auth-schemes'
import {
  ServiceSchema,
  ServiceDetailSchema,
  CreateServiceRequestSchema,
  ErrorSchema,
  OkSchema,
  OkWithSlugSchema,
} from './routes/services'
import {
  CredentialSchema,
  CreateCredentialRequestSchema,
} from './routes/credentials'
import {
  RevokeTokenRequestSchema,
  RevokeTokenResponseSchema,
} from './routes/tokens'

export const openAPIDocumentation = {
  openapi: '3.1.0',
  info: {
    title: 'agent.pw API',
    version: '1.0.0',
    description: 'API for managing services, credentials, tokens, and proxying authenticated requests.',
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
    { name: 'services', description: 'Service registration and management' },
    { name: 'credentials', description: 'Credential storage and retrieval' },
    { name: 'tokens', description: 'Token management' },
    { name: 'proxy', description: 'Authenticated proxy' },
    { name: 'auth', description: 'Authentication endpoints' },
  ],
}

/** All Zod schemas with .meta({ id }) for injection into components.schemas. */
export const allSchemas = [
  AuthScheme,
  ServiceSchema,
  ServiceDetailSchema,
  CreateServiceRequestSchema,
  ErrorSchema,
  OkSchema,
  OkWithSlugSchema,
  CredentialSchema,
  CreateCredentialRequestSchema,
  RevokeTokenRequestSchema,
  RevokeTokenResponseSchema,
]
