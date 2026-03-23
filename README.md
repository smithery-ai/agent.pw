# agent.pw

[![npm version](https://img.shields.io/npm/v/agent.pw)](https://www.npmjs.com/package/agent.pw)

`agent.pw` is a credential vault and auth framework for agents.

It lets agent products connect to external services once and reuse those credentials safely across agents, tools, and MCP clients.

Host products embed it in-process to manage provider OAuth and API keys, store encrypted credentials, and resolve fresh authenticated headers at runtime.

The framework centers on five concepts:

- `Credential Profile`: a reusable auth definition for providers that need one
- `Auth Binding`: one saved connection in your product and the auth target it uses
- `Credential`: encrypted auth material stored under a binding root
- `OAuth`: start, complete, refresh, and disconnect provider auth flows
- `Rules`: portable authorization facts that can be enforced directly or compiled into Biscuits

## Package Surface

```ts
import { createAgentPw } from 'agent.pw'
import * as paths from 'agent.pw/paths'
import * as oauth from 'agent.pw/oauth'
import * as rules from 'agent.pw/rules'
import * as biscuit from 'agent.pw/biscuit'
import * as sql from 'agent.pw/sql'
```

## Quick Start

```ts
import { createAgentPw } from 'agent.pw'
import { createDb } from 'agent.pw/sql'
import { createInMemoryFlowStore } from 'agent.pw/oauth'

const db = createDb(process.env.DATABASE_URL!)

const agentPw = await createAgentPw({
  db,
  encryptionKey: process.env.AGENTPW_ENCRYPTION_KEY!,
  flowStore: createInMemoryFlowStore(),
})

await agentPw.profiles.put('/github', {
  host: ['api.github.com'],
  auth: {
    authSchemes: [
      {
        type: 'oauth2',
        authorizeUrl: 'https://github.com/login/oauth/authorize',
        tokenUrl: 'https://github.com/login/oauth/access_token',
      },
    ],
  },
  oauthConfig: {
    clientId: process.env.GITHUB_CLIENT_ID!,
    clientSecret: process.env.GITHUB_CLIENT_SECRET!,
    scopes: ['repo'],
  },
})

const binding = {
  root: '/acme/connections/github_primary',
  target: {
    kind: 'profile',
    profilePath: '/github',
  },
}

const session = await agentPw.oauth.startAuthorization({
  ...binding,
  redirectUri: 'https://connect.example.com/oauth/callback',
})

// Redirect the user to session.authorizationUrl, then later:
await agentPw.oauth.completeAuthorization({
  callbackUri: 'https://connect.example.com/oauth/callback?code=...&state=...',
})

const headers = await agentPw.bindings.resolveHeaders(binding)
```

`createInMemoryFlowStore()` is a development helper. Multi-instance products should pass an explicit persistent or shared `FlowStore`.

## Auth Bindings

The framework runtime contract is explicit:

1. define or resolve a `Credential Profile`
2. create an `Auth Binding` for a connection in your product
3. start and complete auth against that binding
4. resolve headers or stored credentials from the same binding later

A binding is how your product tells agent.pw, "this saved connection should use this auth target."

Every binding has:

- `root`: where credentials for this connection live
- `target`: how this connection authenticates

`target` can be one of two things:

- a `Credential Profile`, for APIs that need an explicit auth definition or an override
- a discovered `resource`, for MCP servers and other OAuth resources that publish their own metadata

Profile-based example:

```ts
const binding = {
  root: '/acme/connections/github_primary',
  target: {
    kind: 'profile',
    profilePath: '/github',
  },
}
```

Discovery-first example:

```ts
const binding = {
  root: '/acme/connections/docs_mcp',
  target: {
    kind: 'resource',
    resource: 'https://docs.example.com/mcp',
  },
}
```

For a saved connection such as "Acme GitHub", the binding tells agent.pw:

- where to read or store credentials for that connection
- whether auth comes from a profile or from resource discovery

`root` answers "which part of the path tree belongs to this connection?"

`target` answers "how should this connection authenticate?"

That is why the binding uses `root + target`.

- `root` is a lookup boundary and sharing boundary
- `credentialPath` is an optional exact leaf when the caller already knows the specific credential to use
- if no `credentialPath` is provided, agent.pw resolves the deepest matching credential under the binding root

In practice, host products usually know "this is Acme's GitHub connection" or "this is the docs MCP connection" before they know the exact credential leaf. The binding starts from that connection root, and `credentialPath` stays available as an optional override when the caller wants to pin one specific stored credential.

The shorthand `{ root, profilePath }` is still accepted for profile-based bindings. The more general form is `{ root, target }`.

Runtime resolution does not depend on request hosts, proxy headers, or a framework-owned HTTP server.

## Discovery-First MCP OAuth

When a server publishes OAuth discovery metadata, agent.pw can use it directly without requiring a `Credential Profile`.

```ts
const discovered = await agentPw.oauth.discoverResource({
  resource: 'https://docs.example.com/mcp',
})

const binding = {
  root: '/acme/connections/docs_mcp',
  target: discovered.target,
}

const session = await agentPw.oauth.startAuthorization({
  ...binding,
  redirectUri: 'https://connect.example.com/oauth/callback',
  client: {
    metadata: {
      redirectUris: ['https://connect.example.com/oauth/callback'],
      clientName: 'Connect Client',
      tokenEndpointAuthMethod: 'none',
    },
    useDynamicRegistration: true,
  },
})

await agentPw.oauth.completeAuthorization({
  callbackUri: 'https://connect.example.com/oauth/callback?code=...&state=...',
})

const headers = await agentPw.bindings.resolveHeaders(binding)
```

Use a `Credential Profile` when you need a polyfill or override for services that do not publish usable discovery metadata.

## Hosted OAuth and CIMD

`agent.pw` includes helpers for embedded products that want to host the OAuth callback flow and serve a client metadata document for MCP-style clients.

```ts
const oauthHandlers = agentPw.oauth.createWebHandlers({
  callbackPath: '/oauth/callback',
})

export async function start(request: Request) {
  return oauthHandlers.start(request, {
    root: '/acme/connections/github_primary',
    target: {
      kind: 'profile',
      profilePath: '/github',
    },
  })
}

export async function callback(request: Request) {
  return oauthHandlers.callback(request)
}

export async function clientMetadata() {
  return agentPw.oauth.createClientMetadataResponse({
    clientId: 'https://connect.example.com/.well-known/oauth-client',
    redirectUris: ['https://connect.example.com/oauth/callback'],
    clientName: 'Connect Client',
    scope: ['mcp.tools.read', 'mcp.resources.read'],
    tokenEndpointAuthMethod: 'none',
  })
}
```

The hosted helper surface is:

- `startAuthorization(...)`
- `completeAuthorization(...)`
- `refreshCredential(...)`
- `disconnect(...)`
- `createWebHandlers(...)`
- `createClientMetadataDocument(...)`
- `createClientMetadataResponse(...)`

Under the hood, OAuth is implemented with [`oauth4webapi`](https://github.com/panva/oauth4webapi).

## Rules and Tokens

Use `agent.pw/rules` for path-based policy checks directly in application code:

```ts
import { authorizeRules } from 'agent.pw/rules'

const result = authorizeRules({
  rights: [{ action: 'credential.use', root: '/acme' }],
  action: 'credential.use',
  path: '/acme/connections/github_primary',
})
```

Use `agent.pw/biscuit` when you want to compile the same rules into Biscuit tokens:

```ts
import { compileRulesToBiscuit, subjectFactsToExtraFacts } from 'agent.pw/biscuit'

const token = compileRulesToBiscuit({
  privateKeyHex: process.env.BISCUIT_PRIVATE_KEY!,
  subject: 'agent_finance',
  rights: [{ action: 'credential.use', root: '/acme' }],
  constraints: [{ hosts: ['api.github.com'], ttl: '10m' }],
  extraFacts: subjectFactsToExtraFacts({
    orgId: 'acme',
    scopes: ['repo'],
  }),
})
```

Host products can use Biscuits, another token format, or no bearer token format at all. The framework exposes the rule model either way.

## Path Model

Every durable object lives on a canonical slash-delimited path:

```txt
/github
/acme/github
/acme/ws_eng/github
/acme/connections/github_primary
/acme/ws_eng/user_alice/notion
```

The path model applies to:

- `Credential Profiles`
- `Credentials`
- `Auth Binding` roots
- authorization roots in `Rules`

Resolution is tree-based:

- profiles resolve by deepest applicable path, with root-level defaults as fallback
- credentials resolve by deepest stored credential under an explicit binding root
- same-depth ambiguity is an error the host product must disambiguate

## SQL

`agent.pw` is SQL-first. The repo ships:

- Drizzle schema in the `agentpw` schema
- query helpers and local bootstrap utilities
- generated migrations in [`drizzle`](./drizzle)

Current framework tables:

- `cred_profiles`
- `credentials`

The default namespace is the `agentpw` schema with no table prefix.

Embedders can opt into a different SQL namespace without changing the default package path:

```ts
import { createAgentPwSchema, createDb } from 'agent.pw/sql'

const sqlNamespace = createAgentPwSchema({
  schema: 'connect_data',
  tablePrefix: 'smithery_',
})

const db = createDb(process.env.DATABASE_URL!, {
  sql: sqlNamespace,
})

const agentPw = await createAgentPw({
  db,
  encryptionKey: process.env.AGENTPW_ENCRYPTION_KEY!,
  sql: sqlNamespace,
})
```

## Public Docs

The OSS repo is the source of truth for the public architecture:

- [docs/architecture.md](./docs/architecture.md)
- [docs/security-model.md](./docs/security-model.md)

## Development

```bash
pnpm install
pnpm lint
pnpm typecheck
pnpm test
pnpm run db:generate
```

## Repo Structure

```txt
packages/server/src/
  index.ts          createAgentPw(...)
  oauth.ts          provider OAuth runtime and hosted helpers
  paths.ts          canonical path helpers
  rules.ts          rule evaluation helpers
  biscuit.ts        optional Biscuit compilation and verification helpers
  db/               Drizzle schema, queries, bootstrap, migrations
  lib/              encryption, logging, shared helpers
docs/
  architecture.md
  security-model.md
```
