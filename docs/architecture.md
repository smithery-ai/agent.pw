# Architecture

## Executive Summary

The framework has four core resource types and two runtime layers.

Resources:

- `Credential Profile`: how a provider authenticates at a path
- `Auth Binding`: the runtime handle for one saved connection in a host product
- `Credential`: encrypted auth material stored under that root
- `Rules`: path-based authorization facts over one or more roots

Runtime layers:

- `OAuth`: start, complete, refresh, and disconnect provider auth
- optional token compilation helpers such as `agent.pw/biscuit`

The primary runtime contract is explicit. Products pass an `Auth Binding` with `root + target`. Runtime credential resolution starts from that binding rather than from inferred hosts, proxy headers, or framework-owned routes.

## Package Boundary

The public package surface is:

```ts
import { createAgentPw } from 'agent.pw'
import * as paths from 'agent.pw/paths'
import * as oauth from 'agent.pw/oauth'
import * as rules from 'agent.pw/rules'
import * as biscuit from 'agent.pw/biscuit'
import * as sql from 'agent.pw/sql'
```

`createAgentPw(...)` returns namespaces, not an HTTP app:

- `profiles`
- `bindings`
- `credentials`
- `oauth`

There is no built-in server, daemon, CLI, or proxy surface in this repo.

## Concepts

### Path

Every durable object lives on a canonical absolute slash-delimited path.

Examples:

```txt
/github
/acme/github
/acme/ws_eng/github
/acme/connections/github_primary
/acme/ws_eng/user_alice/notion
```

The framework does not store folder rows. Hierarchy is implicit in path segments.

### Credential Profile

A `Credential Profile` defines how to authenticate to a provider at a path.

Profiles can include:

- provider hosts
- supported auth schemes
- OAuth client and endpoint configuration
- org- or workspace-specific overrides

Profiles are tree-scoped. Examples:

```txt
/github
/acme/github
/acme/ws_eng/github
```

Deeper profiles override broader ones when both apply.

Profiles are optional for discovery-first OAuth resources. They are most useful when a product needs an explicit auth definition, a polyfill, or a path-scoped override.

### Auth Binding

A binding is how a host product tells agent.pw which saved connection it wants to use and how that connection authenticates.

It tells the framework two things:

- `root`: which path subtree to use for storing and resolving credentials
- `target`: how that connection authenticates

`target` can be:

- `{ kind: 'profile', profilePath }` when the product wants to use a `Credential Profile`
- `{ kind: 'resource', resource }` when the product wants discovery-first OAuth for a published resource such as an MCP server

Examples:

```txt
/acme/connections/github_primary
/acme/connections/linear_finance
/{namespace}/{connectionId}
```

Bindings are the primary runtime identity model for embedded consumers such as Smithery Connect.

If your product has a connection called "Acme GitHub", the binding might look like:

```ts
const binding = {
  root: '/acme/connections/github_primary',
  target: {
    kind: 'profile',
    profilePath: '/github',
  },
}
```

A discovery-first MCP binding might look like:

```ts
const binding = {
  root: '/acme/connections/docs_mcp',
  target: {
    kind: 'resource',
    resource: 'https://docs.example.com/mcp',
  },
}
```

`root` answers "which part of the path tree belongs to this connection for credential lookup and storage?"

`target` answers "how should this connection authenticate?"

That is why the binding is `root + target`.

- `root` is a namespace boundary and lookup boundary
- `credentialPath` is an optional exact leaf when a caller wants to pin one specific stored credential
- when `credentialPath` is omitted, the framework resolves the deepest matching credential under the binding root

In practice, a host product usually knows it is working with a connection such as "Acme GitHub" or "Docs MCP" before it knows the exact credential leaf. The binding starts from that connection root, and `credentialPath` remains an optional override for callers that want to pin one specific stored credential.

For compatibility, the framework still accepts the shorthand `{ root, profilePath }` for profile-backed bindings.

### Credential

A `Credential` is encrypted auth material stored at a path under a binding root.

Credentials are tagged with their auth target. Runtime resolution uses:

- the binding root
- the binding target
- the deepest stored matching credential inside that root

Examples:

```txt
/acme/connections/github_primary/github
/acme/ws_eng/user_alice/notion_personal
/acme/shared/linear_bot
```

### Rules

`Rules` are the base authorization model for the framework.

Each rule is a path grant:

```txt
action = credential.use
root   = /acme
```

The framework can:

- evaluate those rules directly in application code
- derive root visibility for list or runtime operations
- compile the same rule set into Biscuits when a host product wants capability tokens

## Resolution Model

### Profile Resolution

Profile resolution is path-based:

1. start from a candidate root
2. find profiles whose parent path is an ancestor of that root
3. prefer the deepest applicable match
4. fall back to a global default such as `/github`
5. same-depth ambiguity is an error

### Binding-First Runtime Resolution

Runtime credential resolution starts from an explicit binding:

1. the host product chooses `root + target`
2. for profile targets, `agent.pw` resolves the `Credential Profile`
3. for resource targets, `agent.pw` uses discovery metadata directly
4. `agent.pw` looks for credentials under the binding root tagged to that same target
5. the deepest stored credential wins
6. same-depth ambiguity is an error

The framework still stores `host` on credentials because host products may want it as metadata or for adapter logic. It is not the canonical runtime identity model.

An explicit `credentialPath` can still be passed when the caller already knows the exact credential to use. That narrows runtime resolution further, but it is optional and does not replace the binding root.

### Refresh-Aware Resolution

`bindings.resolve(...)` and `bindings.resolveHeaders(...)` are refresh-aware.

If a resolved credential contains refreshable OAuth state and the access token is expired or near expiry, the framework:

1. resolves the binding
2. refreshes the provider token if needed
3. persists the new credential state
4. returns fresh headers

That means embedded products can call binding resolution directly during runtime use instead of re-implementing token freshness logic outside the framework.

## OAuth Runtime

OAuth is implemented with `oauth4webapi`.

The framework owns:

- PKCE authorization start
- callback completion and code exchange
- refresh token exchange
- optional disconnect and token revocation
- resource metadata discovery and authorization server discovery
- hosted callback helpers
- client metadata document generation for MCP-style clients

The framework does not require an app-auth framework or a second server hop.

### Flow State

Pending OAuth handoff state is stored behind a `FlowStore` interface:

```ts
interface FlowStore {
  create(flow: PendingFlow): Promise<void>
  get(id: string): Promise<PendingFlow | null>
  complete(id: string, result?: { identity?: string }): Promise<void>
  delete(id: string): Promise<void>
}
```

This lets one embedded product use SQL, another use KV, and another use an in-memory store for local development. `createInMemoryFlowStore()` is explicit and intended for development or tests.

### Hosted OAuth and CIMD

Many MCP clients need a hosted callback and a client metadata document.

`agent.pw` provides both:

- `oauth.createWebHandlers(...)`
- `oauth.createClientMetadataDocument(...)`
- `oauth.createClientMetadataResponse(...)`

That gives embedded products a small hosted surface without making HTTP routing part of the core contract.

## Storage Model

`agent.pw` is SQL-first. By default, framework tables live in the `agentpw` schema.

Current tables:

- `cred_profiles`
- `credentials`

Important storage choices:

- `cred_profiles.path` and `credentials.path` are tree-aware path fields
- `credentials.profile_path` stores the canonical auth target key used for runtime resolution
- secrets are encrypted before persistence
- the SQL schema is framework-owned and versioned with Drizzle migrations

The default namespace is `agentpw` with no table prefix, but embedders can override both through `createAgentPwSchema(...)` and pass the same namespace config into:

- `createDb(...)` or `createLocalDb(...)`
- `migrateLocal(...)` or `bootstrapLocalSchema(...)`
- `createAgentPw(...)`

That keeps the default package behavior stable while allowing a host product to place agent.pw tables inside its own schema or prefixed namespace.

## Rules and Biscuit Compilation

The framework treats rules as primary and Biscuit as optional.

`agent.pw/rules` is the portable enforcement layer:

- `authorizeRules(...)`
- `rootsForAction(...)`
- `coveringRootsForPath(...)`
- `constraintAppliesToPath(...)`

`agent.pw/biscuit` is the optional compiler and transport helper:

- `compileRulesToBiscuit(...)`
- `mintToken(...)`
- `restrictToken(...)`
- `authorizeRequest(...)`
- `extractTokenFacts(...)`

This keeps the authorization model stable even if host products choose a different bearer token format later.

## Embedded Consumer Flow

An embedded consumer such as Smithery Connect uses the framework like this:

1. choose a binding root such as `/{namespace}/{connectionId}`
2. choose an auth target:
   - a `Credential Profile` such as `/github`
   - or a discovered resource such as `https://docs.example.com/mcp`
3. start OAuth for that binding
4. complete OAuth and persist a credential under the binding root
5. resolve headers from that binding during MCP or API execution
6. apply rules directly or compile them into Biscuits for downstream runtimes

The product stays in control of discovery, UX, and runtime orchestration. `agent.pw` owns the auth substrate underneath.
