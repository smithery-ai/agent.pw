# agent.pw

[![npm version](https://img.shields.io/npm/v/agent.pw)](https://www.npmjs.com/package/agent.pw)

`agent.pw` is an embeddable auth and credential framework for agent products.

It gives a host application four things:

- path-scoped `Credential Profiles` that describe how a provider authenticates
- encrypted `Credentials` stored once and reused across runtimes
- scoped Biscuit-based `Agent Access` tokens for agent execution
- a Better Auth bridge that mirrors provider OAuth accounts into agent.pw credentials

Smithery-style products embed `agent.pw` directly in-process. There is no built-in server, daemon, or CLI in this repo.

## Package Surface

```ts
import { createAgentPw } from 'agent.pw'
import * as paths from 'agent.pw/paths'
import * as access from 'agent.pw/access'
import * as sql from 'agent.pw/sql'
import * as betterAuth from 'agent.pw/better-auth'
```

## Quick Start

```ts
import { createAgentPw } from 'agent.pw'
import { createDb } from 'agent.pw/sql'

const db = createDb(process.env.DATABASE_URL!)

const agentPw = await createAgentPw({
  db,
  biscuitPrivateKey: process.env.BISCUIT_PRIVATE_KEY!,
})

await agentPw.profiles.put('/linear', {
  host: ['api.linear.app'],
  auth: {
    authSchemes: [
      {
        type: 'oauth2',
        authorizeUrl: 'https://linear.app/oauth/authorize',
        tokenUrl: 'https://api.linear.app/oauth/token',
      },
    ],
  },
  oauthConfig: {
    clientId: process.env.LINEAR_CLIENT_ID,
  },
})

await agentPw.credentials.put('/org_acme/linear', {
  host: 'api.linear.app',
  auth: { kind: 'headers' },
  secret: {
    headers: {
      Authorization: `Bearer ${process.env.LINEAR_API_KEY}`,
    },
  },
})

const credential = await agentPw.credentials.resolve({
  host: 'api.linear.app',
  root: '/org_acme/workflows/finance',
})

const accessToken = await agentPw.access.mint({
  rights: [{ action: 'credential.use', root: '/org_acme' }],
  owner: {
    userId: 'usr_123',
    orgId: 'org_acme',
    homePath: '/org_acme',
    name: 'Finance agent',
  },
})
```

## Better Auth

`agent.pw/better-auth` exports:

- `betterAuthSchema` for Better Auth Drizzle adapters in the `agentpw` schema
- `createAgentPwBetterAuthPlugin(...)` to mirror Better Auth provider accounts into encrypted agent.pw credentials

```ts
import { betterAuth } from 'better-auth'
import { drizzleAdapter } from 'better-auth/adapters/drizzle'
import { genericOAuth } from 'better-auth/plugins'
import { createAgentPwBetterAuthPlugin, betterAuthSchema } from 'agent.pw/better-auth'

const auth = betterAuth({
  database: drizzleAdapter(db, {
    provider: 'pg',
    schema: betterAuthSchema,
  }),
  plugins: [
    genericOAuth({
      config: [
        {
          providerId: 'linear',
          authorizationUrl: 'https://linear.app/oauth/authorize',
          tokenUrl: 'https://api.linear.app/oauth/token',
          clientId: process.env.LINEAR_CLIENT_ID!,
          clientSecret: process.env.LINEAR_CLIENT_SECRET!,
          scopes: ['read', 'write'],
        },
      ],
    }),
    createAgentPwBetterAuthPlugin({
      agentPw,
      selectCredential() {
        return {
          credentialPath: '/org_acme/linear',
          provider: 'linear',
        }
      },
    }),
  ],
})
```

The Better Auth bridge keeps runtime reads on agent.pw credentials, not on Better Auth account rows directly.

## Path Model

Every durable object in agent.pw lives on a canonical slash-delimited path.

Examples:

```txt
/linear
/org_acme/linear
/org_acme/ws_eng/linear
/org_acme/ws_eng/user_alice/notion
```

- `Credential Profile`: auth definition at a path
- `Credential`: encrypted auth material at a path
- `Agent Access`: scoped rights over one or more path roots

Resolution is tree-based:

- profiles resolve by deepest applicable path, with root-level defaults as fallback
- credentials resolve by deepest applicable stored credential
- same-depth ambiguity is an error that the host product must disambiguate

More detail is in [docs/security-model.md](docs/security-model.md).

## SQL

`agent.pw` is SQL-first. The repo ships:

- Drizzle schema under the `agentpw` schema
- local bootstrap helpers for PGlite
- generated migrations in [`drizzle`](drizzle)

Key tables:

- `cred_profiles`
- `credentials`
- `issued_tokens`
- `revocations`
- Better Auth companion tables:
  - `auth_users`
  - `auth_sessions`
  - `auth_accounts`
  - `auth_verifications`

## Development

```bash
pnpm install
pnpm build
pnpm test
pnpm run lint
pnpm run db:generate
```

## Repo Structure

```txt
packages/server/src/
  index.ts          createAgentPw(...)
  access.ts         Biscuit-backed access helpers and service
  paths.ts          canonical path helpers
  better-auth/      Better Auth bridge and schema exports
  db/               Drizzle schema, queries, bootstrap, migrations
  lib/              encryption, logging, shared helpers
docs/
  security-model.md
```

## License

[FSL-1.1-MIT](LICENSE.md) — converts to MIT after two years.
