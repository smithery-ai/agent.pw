# Credential Profiles

Credential profiles are admin-configured setup guidance for `agent.pw`.

They are the right tool when an embedder wants to:

- declare the exact HTTP headers an app may collect
- declare required query params that must stay in the resource URL
- prefer a fixed OAuth setup over generic discovery
- combine required HTTP inputs with OAuth for one provider
- apply defaults globally and override them for specific orgs or workspaces

Profiles are configuration, not secrets. End users usually should not need to know they exist.

## Public Profile Shape

Profiles can define:

- `http.headers`
- `http.query`
- `oauth`

They can be:

- HTTP-only
- OAuth-only
- HTTP + OAuth

Example:

```ts
await agentPw.profiles.put("browserbase", {
  resourcePatterns: ["https://browserbase.run.tools*"],
  displayName: "Browserbase",
  http: {
    headers: {
      "x-api-key": {
        label: "API Key",
        description: "Browserbase API key",
        required: true,
      },
    },
    query: {
      projectId: {
        label: "Project ID",
        description: "Browserbase project",
        required: true,
      },
    },
  },
});
```

HTTP input values are literal:

- query params stay in the `resource` URL
- headers are stored through `connect.setHeaders(...)`
- profiles do not support `prefix`, `secret`, `writeOnly`, or other value formatting metadata

## What Profiles Affect

Profiles participate in guided setup through `connect.prepare(...)`.

They do not change what kinds of credentials the vault can store. They only influence how the framework decides what the app should do next for a given `path` and `resource`.

In practice:

- if an exact-path credential already exists, that credential wins
- otherwise `agent.pw` looks for matching profiles
- if a matching profile exists and required HTTP inputs are missing, `agent.pw` returns `input_required`
- if a matching profile exists and OAuth applies, `agent.pw` returns a `source: "profile"` OAuth option
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

## Resolution Order

For a guided connection attempt, `agent.pw` resolves in this order:

1. exact-path stored credential
2. matching credential profile
3. if required profile HTTP inputs are missing, `input_required`
4. profile-backed OAuth or discovery-backed OAuth
5. unconfigured

This is important for embedders:

- profiles are a setup-time override for fresh attempts
- profiles do not automatically replace an already-stored exact-path credential
- manual HTTP setup is represented by `input_required`, not by a public `headers` option

## HTTP Input Profiles

HTTP input profiles define what an app may collect and which fields are required.

```ts
await agentPw.profiles.put("resend", {
  resourcePatterns: ["https://api.resend.com*"],
  displayName: "Resend",
  http: {
    headers: {
      Authorization: {
        label: "API key",
        description: "Your Resend API key",
        required: true,
      },
    },
  },
});
```

When that profile matches, `connect.prepare(...)` returns `input_required` until the required inputs are satisfied.

Query params are not stored in `agent.pw`. They stay in the resource URL:

```ts
const prepared = await agentPw.connect.prepare({
  path: "acme.connections.browserbase",
  resource: "https://browserbase.run.tools/mcp",
});

if (prepared.kind === "input_required") {
  console.log(prepared.input.http);
  console.log(prepared.input.missing);
}
```

After the app has collected header values, it stores them with `connect.setHeaders(...)`:

```ts
await agentPw.connect.setHeaders({
  path: "acme.connections.resend",
  resource: "https://api.resend.com",
  headers: {
    Authorization: "Bearer rs_live_123",
  },
});
```

Then the app calls `connect.prepare(...)` again using the updated resource URL if required query params changed.

## OAuth Profiles

OAuth profiles define a fixed OAuth setup to use when discovery is not enough or when an embedder wants to override it intentionally.

```ts
await agentPw.profiles.put("linear", {
  resourcePatterns: ["https://api.linear.app/*"],
  displayName: "Linear",
  oauth: {
    authorizationUrl: "https://linear.app/oauth/authorize",
    tokenUrl: "https://api.linear.app/oauth/token",
    clientId: process.env.LINEAR_CLIENT_ID!,
    clientSecret: process.env.LINEAR_CLIENT_SECRET!,
    scopes: "read write",
  },
});
```

When that profile matches, `connect.prepare(...)` returns `source: "profile"` and `connect.startOAuth(...)` uses the profile-backed path instead of discovery.

## HTTP + OAuth Profiles

Some services require both connection inputs and OAuth. Profiles can model that directly.

```ts
await agentPw.profiles.put("docs", {
  resourcePatterns: ["https://docs.example.com/*"],
  displayName: "Docs",
  http: {
    headers: {
      "x-api-key": {
        label: "API Key",
        required: true,
      },
    },
    query: {
      workspaceId: {
        label: "Workspace ID",
        required: true,
      },
    },
  },
  oauth: {
    authorizationUrl: "https://accounts.example.com/authorize",
    tokenUrl: "https://accounts.example.com/token",
    clientId: process.env.DOCS_CLIENT_ID!,
  },
});
```

For that profile:

1. `connect.prepare(...)` returns `input_required` until the required headers and query params are present
2. once the required HTTP inputs are satisfied, `connect.prepare(...)` returns the profile-backed OAuth option
3. after OAuth completes, the connection becomes a normal stored credential

## Trusted Provider Override Example

One common advanced use case is a trusted provider with broken or incomplete discovery metadata.

An embedder can install a profile that applies to every matching Cloudflare Observability resource:

```ts
await agentPw.profiles.put("cloudflare.observability", {
  resourcePatterns: ["https://observability.mcp.cloudflare.com/*"],
  displayName: "Cloudflare Observability",
  oauth: {
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

## Global Defaults and Scoped Overrides

Profiles can express both global defaults and scoped overrides.

Example:

```ts
await agentPw.profiles.put("cloudflare", {
  resourcePatterns: ["https://*.cloudflare.com/*"],
  oauth: {
    issuer: "https://dash.cloudflare.com",
  },
});

await agentPw.profiles.put("acme.cloudflare", {
  resourcePatterns: ["https://observability.mcp.cloudflare.com/*"],
  oauth: {
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
- store query values for you
- define formatting or secrecy rules for input values

## When To Use Profiles

Use a profile when:

- the provider publishes no usable discovery metadata
- the provider discovery path is known-bad and you trust a fixed configuration more
- you want a stable OAuth setup owned by the embedder
- you want a literal admin-facing template for required HTTP inputs

Do not use a profile when:

- discovery already works and you do not need to override it
- you only need to store a one-off credential at a single path

## Related Docs

- [Getting Started](./getting-started.md)
- [Reference](./reference.md)
- [Architecture](./architecture.md)
- [Security Model](./security-model.md)
