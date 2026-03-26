# agent.pw

[![npm version](https://img.shields.io/npm/v/agent.pw)](https://www.npmjs.com/package/agent.pw)

`agent.pw` helps apps connect external resources once and reuse the resulting auth safely across agents, tools, MCP clients, and sandboxed CLIs.

It stores encrypted credentials, runs OAuth flows, supports manual header-based auth, stores env secrets, and resolves fresh authenticated headers or env values from a connection `path`.

## Concepts

- `path`: one saved connection in your app, such as `/acme/connections/github`
- `resource`: the protected resource a connect flow is trying to access, such as `https://api.github.com/` or `https://docs.example.com/mcp`
- `credential`: the encrypted auth stored at that exact path
- `profile`: admin-configured setup guidance and polyfills that help `agent.pw` choose the right auth path
- `rules`: path-based authorization facts that can be enforced directly or compiled into Biscuits

Profiles are background configuration. End users usually do not need to know they exist.

## Package Surface

```ts
import { createAgentPw } from 'agent.pw'
import * as oauth from 'agent.pw/oauth'
import * as rules from 'agent.pw/rules'
import * as biscuit from 'agent.pw/biscuit'
import * as sql from 'agent.pw/sql'
import * as paths from 'agent.pw/paths'
```

`createAgentPw(...)` returns:

- `connect`
- `credentials`
- `profiles`
- `scope(...)`

## Quick Start

```ts
import { createAgentPw } from 'agent.pw'
import { createDb } from 'agent.pw/sql'
import { createInMemoryFlowStore } from 'agent.pw/oauth'

const sql = {
  schema: 'agentpw',
  tablePrefix: '',
}

const db = createDb(process.env.DATABASE_URL!, { sql })

const agentPw = await createAgentPw({
  db,
  sql,
  encryptionKey: process.env.AGENTPW_ENCRYPTION_KEY!,
  flowStore: createInMemoryFlowStore(),
})
```

`createInMemoryFlowStore()` is a development helper. Multi-instance apps should pass a shared or persistent `FlowStore`.

## Guided Connect Flow

The main API is `connect.*`.

```ts
const started = await agentPw.connect.connect({
  path: '/acme/connections/docs',
  resource: 'https://docs.example.com/mcp',
  redirectUri: 'https://app.example.com/oauth/callback',
  context: {
    userId: 'user_123',
    connectionId: 'docs',
  },
})

if (started.kind === 'ready') {
  return started.headers
}

if (started.kind === 'authorization') {
  return Response.redirect(started.session.authorizationUrl, 302)
}

if (started.kind === 'headers') {
  await agentPw.connect.saveHeaders({
    path: '/acme/connections/docs',
    option: started.option,
    values: {
      Authorization: 'api-key-value',
    },
  })
} else {
  throw new Error('This resource is not configured yet')
}
```

Later, resolve fresh headers for that same connection:

```ts
const headers = await agentPw.connect.headers({
  path: '/acme/connections/docs',
})
```

## `connect.prepare(...)`

`connect.prepare(...)` always answers one question:

What should this app do next for this connection path and resource?

It returns one of:

- `ready`: a credential already exists at `path`
- `options`: a list of possible auth routes

Each returned option is self-contained. Apps pass the chosen option into either:

- `connect.start(...)` for OAuth
- `connect.saveHeaders(...)` for manual header-based auth

An empty `options` list means the resource is currently unconfigured.

For framework integrations that do not want to own option-selection logic, use `connect.connect(...)` instead. It returns one of:

- `ready`: a credential already exists
- `authorization`: redirect the browser to OAuth
- `headers`: collect manual header values and call `connect.saveHeaders(...)`
- `unconfigured`: no auth route is currently available

If the flow started because the runtime already observed a real auth challenge, pass `reason: 'auth_required'` into `connect.start(...)` or `connect.connect(...)`. That persists `reason: "auth_required"` and `requiresUpstreamAuthorization: true` inside the flow so continuation code does not have to reconstruct that state from app-owned metadata.

`connect.resolve(...)` exposes the same library decision as structured metadata:

- `canonicalResource`
- `source`: `profile`, `discovery`, or `null`
- `reason`: why that route won
- `profilePath`
- `option`

## Auth Kinds

At the vault level there are three credential kinds:

- `oauth`
- `headers`
- `env`

`connect.*` only guides `oauth` and `headers`.

API keys are header auth. Basic auth, bearer tokens, vendor-specific headers, cookies, and similar schemes are all header auth.

Credentials always store the runtime material they need:

- `oauth` and `headers` credentials store resolved runtime headers
- `env` credentials store env name/value pairs
- OAuth credentials may also store refresh state so `agent.pw` can keep headers fresh

## Profile-Aware OAuth

When a known profile matches, `agent.pw` prefers that profile and skips generic discovery. Otherwise it falls back to resource discovery. MCP servers are one example, but the flow is not MCP-specific.

```ts
const resolution = await agentPw.connect.resolve({
  path: '/acme/connections/docs',
  resource: 'https://docs.example.com/mcp',
  response: unauthorizedResponse,
})

console.log(resolution)
// {
//   canonicalResource: 'https://docs.example.com/mcp',
//   source: 'profile',
//   reason: 'matched-profile',
//   profilePath: '/docs',
//   option: { kind: 'oauth', ... }
// }
```

When the callback returns:

```ts
const completed = await agentPw.connect.complete({
  callbackUri: 'https://app.example.com/oauth/callback?code=...&state=...',
  merge: 'preserve-non-auth-headers',
})

console.log(completed.context)
console.log(completed.reason)
```

Pending OAuth state is readable through the same API surface:

```ts
const flow = await agentPw.connect.getFlow(flowId)
```

`connect.headers(...)` is refresh-aware by default, so apps do not need to re-implement token refresh outside the vault.

## Profiles

Profiles are admin-side configuration. They help `agent.pw` decide what to do when discovery is unavailable, incomplete, or intentionally overridden.

Profiles are useful for:

- OAuth overrides for known resources
- header-based setup templates
- internal APIs that do not publish discovery metadata
- constraining and documenting the headers an app should collect

Header-based profiles define which fields are expected:

```ts
await agentPw.profiles.put('/resend', {
  resourcePatterns: ['https://api.resend.com*'],
  displayName: 'Resend',
  auth: {
    kind: 'headers',
    label: 'Resend API key',
    fields: [
      {
        name: 'Authorization',
        label: 'API key',
        description: 'Your Resend API key',
        prefix: 'Bearer ',
        secret: true,
      },
    ],
  },
})
```

OAuth profiles define the auth configuration the framework should use when discovery is not enough or an admin wants a fixed setup:

```ts
await agentPw.profiles.put('/linear', {
  resourcePatterns: ['https://api.linear.app/*'],
  displayName: 'Linear',
  auth: {
    kind: 'oauth',
    authorizationUrl: 'https://linear.app/oauth/authorize',
    tokenUrl: 'https://api.linear.app/oauth/token',
    clientId: process.env.LINEAR_CLIENT_ID!,
    clientSecret: process.env.LINEAR_CLIENT_SECRET!,
    scopes: 'read write',
  },
})
```

Profiles are path-scoped configuration, so apps can keep global defaults and more specific org or workspace overrides.

Apps can also store env-oriented profile hints for custom admin UIs, but `connect.prepare(...)` does not use them in this version.

## One-Off Credentials

Profiles guide setup, but they do not define what is possible.

Apps can still store a one-off credential directly:

```ts
await agentPw.credentials.put({
  path: '/acme/connections/manual_resend',
  auth: {
    kind: 'headers',
    label: 'Manual Resend key',
    resource: 'https://api.resend.com/',
  },
  secret: {
    headers: {
      Authorization: 'Bearer rs_live_123',
    },
  },
})
```

Store env credentials directly through the vault layer:

```ts
await agentPw.credentials.put({
  path: '/acme/connections/github_cli',
  auth: {
    kind: 'env',
    label: 'GitHub CLI',
  },
  secret: {
    env: {
      GH_TOKEN: process.env.GH_TOKEN!,
    },
  },
})

const githubCli = await agentPw.credentials.get('/acme/connections/github_cli')
const env = githubCli?.secret.env
```

List stored credentials directly under a path:

```ts
const children = await agentPw.credentials.list({
  path: '/acme/connections',
})
```

`credentials.list({ path })` returns direct children only.

## Scoped API

Use `scope(...)` to get a scoped API that enforces rules automatically.

```ts
const api = agentPw.scope({
  rights: [{ action: 'credential.use', root: '/acme' }],
})

const headers = await api.connect.headers({
  path: '/acme/connections/docs',
})
```

Apps are responsible for deriving those rights from whatever auth system they use, such as a Biscuit token, a session, or an internal permission store.

`scope(...)` only accepts the facts the framework actually checks: path-based rights.

## Rules and Biscuits

Rules are the base authorization model.

```ts
import { can } from 'agent.pw/rules'

const allowed = can({
  rights: [{ action: 'credential.use', root: '/acme' }],
  action: 'credential.use',
  path: '/acme/connections/docs',
})
```

if (!allowed) {
  throw new Error('Missing credential.use for /acme/connections/docs')
}

If an app wants Biscuit tokens, it can compile the same rules into Biscuits:

```ts
import { compileRulesToBiscuit } from 'agent.pw/biscuit'

const token = compileRulesToBiscuit({
  privateKeyHex: process.env.BISCUIT_PRIVATE_KEY!,
  subject: 'agent_finance',
  rights: [{ action: 'credential.use', root: '/acme' }],
})
```

## Hosted OAuth and Client Metadata

Apps that need a hosted OAuth callback and a Client ID Metadata Document can use the built-in helpers:

```ts
const handlers = agentPw.connect.createWebHandlers({
  callbackPath: '/oauth/callback',
})

export async function oauthStart(request: Request) {
  return handlers.start(request, {
    path: '/acme/connections/docs',
    option: {
      kind: 'oauth',
      source: 'discovery',
      label: 'Docs',
      resource: 'https://docs.example.com/mcp',
    },
  })
}

export async function oauthCallback(request: Request) {
  return handlers.callback(request)
}

export async function clientMetadata() {
  return agentPw.connect.createClientMetadataResponse({
    clientId: 'https://app.example.com/.well-known/oauth-client',
    redirectUris: ['https://app.example.com/oauth/callback'],
    clientName: 'App Client',
    tokenEndpointAuthMethod: 'none',
  })
}
```

Under the hood, OAuth is implemented with [`oauth4webapi`](https://github.com/panva/oauth4webapi).

## SQL Namespace Configuration

Embedders can place `agent.pw` tables in a custom schema or prefix them:

```ts
const sql = {
  schema: 'platform',
  tablePrefix: 'agentpw_',
}

const db = createDb(process.env.DATABASE_URL!, { sql })

const agentPw = await createAgentPw({
  db,
  sql,
  encryptionKey: process.env.AGENTPW_ENCRYPTION_KEY!,
  flowStore,
})
```

The same `sql` options should be passed to both the database helpers and `createAgentPw(...)`.

Apps own their own SQL migrations or DDL. `agent.pw` exports schema and query helpers, but it does not ship framework-owned migration files.

## More Docs

- [Architecture](./docs/architecture.md)
- [Security Model](./docs/security-model.md)
