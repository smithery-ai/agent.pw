# Architecture

`agent.pw` is an embeddable auth and credential framework for agent products.

This repo is the source of truth for the public architecture. Host products import the framework directly and use it in-process. The framework owns provider auth definitions, credential storage, path-based resolution, OAuth handoff state, and scoped agent access. The host product owns user identity, UI, runtime orchestration, and any adapter surface that turns product events into framework calls.

## Executive Summary

The core architecture has five parts:

- `Credential Profiles` define how a provider authenticates at a path
- `Bindings` attach a product resource to a `root + profilePath`
- `Credentials` store encrypted auth material under that binding root
- `Agent Access` mints and verifies Biscuit-backed rights over path roots
- `FlowStore` keeps pending OAuth handoff state in a backend chosen by the host product

The runtime model is explicit. A host product does not need to resolve credentials from request hosts, proxy headers, or a framework-owned HTTP API. It creates or selects a Binding, starts auth for that Binding, completes auth into a stored Credential, and resolves headers or auth material from that Binding later.

## Package Boundary

The public package surface is:

```ts
import { createAgentPw } from 'agent.pw'
import * as access from 'agent.pw/access'
import * as oauth from 'agent.pw/oauth'
import * as paths from 'agent.pw/paths'
import * as sql from 'agent.pw/sql'
import * as betterAuth from 'agent.pw/better-auth'
```

`createAgentPw(...)` returns framework namespaces, not an HTTP app:

- `profiles`
- `bindings`
- `credentials`
- `oauth`
- `access`

The framework does not ship a built-in server, daemon, or CLI in this repo. Products can still build adapters around it, but those adapters sit outside the core contract.

## Core Objects

### Path

Every durable object lives on a canonical absolute slash-delimited path.

Examples:

```txt
/github
/org_acme/github
/org_acme/ws_eng/shared/github_main
/org_acme/connections/linear_primary
```

The framework does not store folder rows. Hierarchy is implicit in path segments.

### Credential Profile

A `Credential Profile` is the auth definition for a provider at a path.

Profiles carry things like:

- provider hosts
- supported auth schemes
- provider-specific OAuth configuration
- refresh or identity resolution hints

Profiles are tree-scoped. A deeper profile overrides a broader one when both apply.

Examples:

```txt
/github
/org_acme/github
/org_acme/ws_eng/github
```

### Binding

A `Binding` is the explicit association between a host product resource and framework auth state.

A Binding declares:

- `root`: the subtree where credentials for that resource live
- `profilePath`: the `Credential Profile` that resource uses

This is the primary runtime contract of the framework. Host products should pass explicit Bindings to runtime auth operations instead of depending on host inference.

Examples:

```txt
/{namespace}/{connectionId}
/org_acme/connections/linear_primary
/org_acme/automations/billing
```

### Credential

A `Credential` is the encrypted auth material stored at a path under a Binding root.

Credentials are also tagged with the `profilePath` they belong to. Runtime resolution starts from `root + profilePath`, then chooses the deepest matching credential under that root.

Examples:

```txt
/org_acme/shared/github_main
/org_acme/ws_eng/shared/linear_main
/org_acme/ws_eng/user_alice/notion_personal
```

### Agent Access

`Agent Access` is a short-lived Biscuit-backed bearer token plus optional ledger state in `issued_tokens`.

It grants rights such as:

- `credential.use`
- `credential.manage`
- `token.mint`

over explicit path roots.

## Resolution Model

### Binding-First Runtime Resolution

The core runtime flow is:

1. The host product chooses or creates a Binding.
2. The host product starts auth for that Binding when needed.
3. Auth completion stores or refreshes a Credential under the Binding root.
4. Runtime code resolves headers or auth material from the same Binding.

The framework surface for that is intentionally direct:

- `bindings.put(...)`
- `bindings.resolve(...)`
- `bindings.resolveHeaders(...)`
- `oauth.start(...)`
- `oauth.complete(...)`

### Profile Resolution

Profiles are resolved by path applicability:

1. Start from a candidate root.
2. Find profiles whose parent path is an ancestor of that root.
3. Prefer the deepest applicable profile.
4. Fall back to root-level defaults such as `/github` or `/linear`.
5. Same-depth ambiguity is an error the host product must disambiguate.

### Credential Resolution

Credential resolution is binding-scoped:

1. Start from the Binding’s `root` and `profilePath`.
2. Keep credentials inside that root whose `profilePath` matches.
3. Choose the deepest applicable credential path.
4. Same-depth ambiguity is an error.

The framework still stores `host` on credentials because host products may want that metadata and some adapters may still infer Bindings from request shape. Host inference is not the canonical runtime identity model.

### Adapters and Inference

Products may build adapters that infer a Binding from:

- request host
- request URL
- product-specific metadata
- user-selected defaults

That inference belongs at the adapter boundary. Once a Binding is known, adapters should call the same binding-based framework APIs that embedded products use directly.

## OAuth and Better Auth

`agent.pw` uses Better Auth as the provider OAuth engine.

The Better Auth bridge:

- exposes Better Auth tables in the same `agentpw` schema
- mirrors provider account updates into encrypted framework Credentials
- keeps runtime reads on `agent.pw` credentials, not on Better Auth account rows

Pending OAuth handoff state is deliberately backend-agnostic.

The framework exposes `agent.pw/oauth` with a `FlowStore` interface:

```ts
interface FlowStore {
  create(flow: PendingFlow): Promise<void>
  get(id: string): Promise<PendingFlow | null>
  complete(id: string, result?: { identity?: string }): Promise<void>
  delete(id: string): Promise<void>
}
```

That allows one host to keep pending auth state in SQL and another to keep it in KV or another ephemeral store without changing the core runtime contract.

## Storage Model

`agent.pw` is SQL-first. All framework-owned tables live in the `agentpw` schema.

Core tables:

- `cred_profiles`
- `credentials`
- `issued_tokens`
- `revocations`

Better Auth companion tables:

- `auth_users`
- `auth_sessions`
- `auth_accounts`
- `auth_verifications`

Important storage choices:

- `cred_profiles.path` is tree-aware and path-scoped
- `credentials.path` is the stored credential path
- `credentials.profile_path` is the canonical runtime profile association
- `credentials.host` is retained as metadata and adapter support, not as the primary identity
- OAuth handoff state is not tied to a required `auth_flows` SQL table

## Access Control

The framework uses Biscuit as its capability system.

The access model is:

1. mint authority facts such as `right(root, action)`
2. optionally attenuate with checks over host, method, path, root, service, and TTL
3. verify the token and revocation status
4. verify that its explicit rights cover the requested action and path
5. evaluate attenuation checks against ambient request facts

See [security-model.md](./security-model.md) for the detailed token contract.

## Smithery Connect as an Embedded Consumer

Smithery Connect is the primary managed example of this architecture.

A Smithery-style embedding looks like this:

1. create a connection-scoped Binding root such as `/{namespace}/{connectionId}`
2. resolve or choose a `profilePath` such as `/github`
3. start auth for that Binding
4. complete auth into an encrypted Credential under the Binding root
5. mint short-lived agent access over the appropriate root
6. resolve headers from that Binding during tool execution

This keeps Connect in control of its own discovery, UI, and runtime semantics while reusing the same auth substrate that other host products can embed.

## End-to-End Example

```txt
1. Define a global profile at /github
2. Create a binding root /org_acme/connections/github_prod with profile /github
3. Start OAuth for that binding
4. Complete OAuth and store a credential at /org_acme/connections/github_prod/github
5. Mint an agent token with right("/org_acme/connections/github_prod", "credential.use")
6. Resolve headers from the binding during runtime
7. Use those headers against the provider's native interface
```

The important property is portability. The same authenticated access can move between runtimes and agents because the framework anchors it to a Binding and a path-based root model instead of to one transport-specific integration.
