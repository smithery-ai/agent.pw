# Credential Profiles

Credential profiles are admin-configured setup guidance for `agent.pw`.

They are the right tool when an embedder wants to:

- provide a known-good auth configuration for a resource
- prefer a fixed OAuth setup over generic discovery
- work around broken or incomplete discovery metadata from a trusted server
- define the exact headers an admin UI should collect
- apply defaults globally and override them for specific orgs or workspaces

Profiles are configuration, not secrets. End users usually should not need to know they exist.

## What Profiles Affect

Profiles participate in guided setup through `connect.prepare(...)`.

They do not change what kinds of credentials the vault can store. They only influence how the framework decides what the app should do next for a given `path` and `resource`.

In practice:

- if an exact-path credential already exists, that credential wins
- otherwise `agent.pw` looks for matching profiles
- if a matching profile exists, `agent.pw` returns a `source: "profile"` option and skips generic discovery
- if no profile matches, `agent.pw` falls back to discovery

That makes profiles the main override mechanism for embedders.

## Matching Rules

A profile matches on two dimensions:

- path scope
- `resourcePatterns`

### Path Scope

A profile path scopes where that profile can apply.

Examples:

```txt
github
acme.github
acme.team.github
```

Those paths do not need to equal the final credential path. Instead, they act like configuration anchors:

- `github` can apply anywhere
- `acme.github` applies inside the `acme` subtree
- `acme.team.github` applies inside the `acme.team` subtree

When multiple profiles match, deeper profile paths win first.

For example, with a connection path like:

```txt
acme.team.connections.docs
```

and these profiles:

```txt
github
acme.github
acme.team.github
```

the effective precedence is:

1. `acme.team.github`
2. `acme.github`
3. `github`

### Resource Patterns

Profiles also match on `resourcePatterns`.

Examples:

```ts
resourcePatterns: ["https://api.github.com/*"];
resourcePatterns: ["https://observability.mcp.cloudflare.com/*"];
resourcePatterns: ["https://api.resend.com*"];
```

Patterns are normalized on write. A profile only applies when one of its patterns matches the requested `resource`.

This means a profile can act as a broad provider default or a narrow override for one service surface.

## Resolution Order

For a guided connection attempt, `agent.pw` resolves in this order:

1. exact-path stored credential
2. matching credential profile
3. discovery
4. unconfigured

This is important for embedders:

- profiles are a setup-time override for fresh attempts
- profiles do not automatically replace an already-stored exact-path credential

If a credential already exists at the target path, `connect.prepare(...)` returns `ready` for that credential instead of re-resolving profiles.

## Header Profiles

Header profiles define what an app should collect for manual auth.

```ts
await agentPw.profiles.put("resend", {
  resourcePatterns: ["https://api.resend.com*"],
  displayName: "Resend",
  auth: {
    kind: "headers",
    label: "Resend API key",
    fields: [
      {
        name: "Authorization",
        label: "API key",
        description: "Your Resend API key",
        prefix: "Bearer ",
        secret: true,
      },
    ],
  },
});
```

When that profile matches, `connect.prepare(...)` returns a `headers` option with the profile metadata the app can render.

## OAuth Profiles

OAuth profiles define a fixed OAuth setup to use when discovery is not enough or when an embedder wants to override it intentionally.

```ts
await agentPw.profiles.put("linear", {
  resourcePatterns: ["https://api.linear.app/*"],
  displayName: "Linear",
  auth: {
    kind: "oauth",
    authorizationUrl: "https://linear.app/oauth/authorize",
    tokenUrl: "https://api.linear.app/oauth/token",
    clientId: process.env.LINEAR_CLIENT_ID!,
    clientSecret: process.env.LINEAR_CLIENT_SECRET!,
    scopes: "read write",
  },
});
```

When that profile matches, `connect.prepare(...)` returns `source: "profile"` and `connect.startOAuth(...)` uses the profile-backed path instead of discovery.

## Trusted Provider Override Example

One common advanced use case is a trusted provider with broken or incomplete discovery metadata.

An embedder can install a profile that applies to every matching Cloudflare Observability resource:

```ts
await agentPw.profiles.put("cloudflare.observability", {
  resourcePatterns: ["https://observability.mcp.cloudflare.com/*"],
  displayName: "Cloudflare Observability",
  auth: {
    kind: "oauth",
    issuer: "https://dash.cloudflare.com",
    clientId: process.env.CLOUDFLARE_CLIENT_ID!,
    clientSecret: process.env.CLOUDFLARE_CLIENT_SECRET!,
    clientAuthentication: "client_secret_post",
  },
});
```

Then, for a fresh connection attempt such as:

```ts
await agentPw.connect.prepare({
  path: "acme.connections.cf_o11y",
  resource: "https://observability.mcp.cloudflare.com/mcp",
});
```

`agent.pw` will prefer the matching profile over generic discovery and return a profile-backed OAuth option.

That is the intended way to polyfill a bad but trusted server without changing the server itself.

## Global Defaults and Scoped Overrides

Profiles can express both global defaults and scoped overrides.

Example:

```ts
await agentPw.profiles.put("cloudflare", {
  resourcePatterns: ["https://*.cloudflare.com/*"],
  auth: { kind: "oauth", issuer: "https://dash.cloudflare.com" },
});

await agentPw.profiles.put("acme.cloudflare", {
  resourcePatterns: ["https://observability.mcp.cloudflare.com/*"],
  auth: {
    kind: "oauth",
    issuer: "https://dash.cloudflare.com",
    clientId: process.env.ACME_CF_CLIENT_ID!,
  },
});
```

With a connection path inside `acme`, the deeper `acme.cloudflare` profile wins over the global one.

## What Profiles Do Not Do

Profiles are powerful, but they are not a forced override layer for every runtime case.

They do not:

- override an already-existing exact-path credential during `connect.prepare(...)`
- attach themselves retroactively to unrelated stored credentials
- replace the need for a caller to choose a connection path
- make `env` profiles part of guided `connect.prepare(...)` in the current version

## When To Use Profiles

Use a profile when:

- the provider publishes no usable discovery metadata
- the provider discovery path is known-bad and you trust a fixed configuration more
- you want a stable OAuth setup owned by the embedder
- you want an admin-facing template for header entry

Do not use a profile when:

- discovery already works and you do not need to override it
- you only need to store a one-off credential at a single path

## Related Docs

- [Architecture](./architecture.md)
- [Security Model](./security-model.md)
