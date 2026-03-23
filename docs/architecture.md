# Architecture

`agent.pw` is a credential vault and auth framework for agents.

This repo is the public source of truth for the architecture. Products embed the framework directly and keep their own UI, user identity, runtime orchestration, and transport layer.

## Executive Summary

The framework has four core resource types and two runtime layers.

Resources:

- `Credential Profile`: how a provider authenticates at a path
- `Binding`: which profile a product resource uses and which root it owns
- `Credential`: encrypted auth material stored under that root
- `Rules`: path-based authorization facts over one or more roots

Runtime layers:

- `OAuth`: start, complete, refresh, and disconnect provider auth
- optional token compilation helpers such as `agent.pw/biscuit`

The primary runtime contract is explicit. Products pass a `Binding` with `root + profilePath`. Runtime credential resolution starts from that binding rather than from inferred hosts, proxy headers, or framework-owned routes.

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

## Core Objects

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

### Binding

A `Binding` is the explicit association between a product resource and framework auth state.

A binding declares:

- `root`: the subtree where credentials for that resource live
- `profilePath`: the credential profile that resource uses

Examples:

```txt
/acme/connections/github_primary
/acme/connections/linear_finance
/{namespace}/{connectionId}
```

Bindings are the primary runtime identity model for embedded consumers such as Smithery Connect.

### Credential

A `Credential` is encrypted auth material stored at a path under a binding root.

Credentials are tagged with their `profilePath`. Runtime resolution uses:

- the binding root
- the binding profile
- the deepest stored matching credential inside that root

Examples:

```txt
/acme/connections/github_primary/github
/acme/ws_eng/user_alice/notion_personal
/acme/shared/linear_bot
```

### Rules

`Rules` are the canonical authorization model for the framework.

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

1. the host product chooses `root + profilePath`
2. `agent.pw` resolves the binding profile
3. `agent.pw` looks for credentials under the binding root with that `profilePath`
4. the deepest stored credential wins
5. same-depth ambiguity is an error

The framework still stores `host` on credentials because host products may want it as metadata or for adapter logic. It is not the canonical runtime identity model.

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

`agent.pw` is SQL-first. All framework tables live in the `agentpw` schema.

Current tables:

- `cred_profiles`
- `credentials`

Important storage choices:

- `cred_profiles.path` and `credentials.path` are tree-aware path fields
- `credentials.profile_path` is the canonical runtime profile association
- secrets are encrypted before persistence
- the SQL schema is framework-owned and versioned with Drizzle migrations

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

1. define a profile such as `/github`
2. choose a binding root such as `/{namespace}/{connectionId}`
3. start OAuth for that binding
4. complete OAuth and persist a credential under the binding root
5. resolve headers from that binding during MCP or API execution
6. apply rules directly or compile them into Biscuits for downstream runtimes

The product stays in control of discovery, UX, and runtime orchestration. `agent.pw` owns the auth substrate underneath.
