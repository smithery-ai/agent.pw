# Getting Started

`agent.pw` is an embeddable auth vault for apps that need to:

- connect a resource once
- store the resulting credential safely
- reuse fresh headers later from one stable path

## Core Model

- `path`: one saved connection in your app, such as `acme.connections.github`
- `resource`: the protected resource a connect flow is targeting, such as `https://api.github.com/` or `https://docs.example.com/mcp`
- `credential`: the encrypted auth stored at that exact path
- `profile`: optional admin-side setup guidance for literal HTTP inputs and OAuth overrides

Profiles are background configuration. End users usually do not need to know they exist.

Paths use strict dot-separated `ltree` syntax. Each segment must match `[A-Za-z0-9_-]+`.

## Create a Vault

```ts
import { createAgentPw } from "agent.pw";
import { createInMemoryFlowStore } from "agent.pw/oauth";
import { createDb } from "agent.pw/sql";
import { unwrap } from "okay-error";

const db = unwrap(createDb(process.env.DATABASE_URL!));

const agentPw = await unwrap(
  createAgentPw({
    db,
    encryptionKey: process.env.AGENTPW_ENCRYPTION_KEY!,
    flowStore: createInMemoryFlowStore(),
  }),
);
```

`createInMemoryFlowStore()` is a development helper. Multi-instance apps should pass a shared or persistent `FlowStore`.

## Guided Connect Flow

The main API is `connect.*`, with `connect.prepare(...)` as the entry point.

```ts
const prepared = await unwrap(
  agentPw.connect.prepare({
    path: "acme.connections.docs",
    resource: "https://docs.example.com/mcp",
  }),
);

if (prepared.kind === "ready") {
  return prepared.headers;
}

if (prepared.kind === "input_required") {
  console.log(prepared.input.http);
  console.log(prepared.input.missing);
  return;
}

const option = prepared.options[0];
if (!option) {
  console.error("This resource is not configured yet");
  return;
}

if (option.kind === "oauth") {
  const session = await unwrap(
    agentPw.connect.startOAuth({
      path: "acme.connections.docs",
      option,
      redirectUri: "https://app.example.com/oauth/callback",
    }),
  );

  return Response.redirect(session.authorizationUrl, 302);
}
```

When `prepared.kind === "input_required"`:

- required query params stay in the `resource` URL
- required headers are stored with `connect.setHeaders(...)`
- after updating either one, call `connect.prepare(...)` again

Later, resolve fresh headers for that same path:

```ts
const headers = await unwrap(
  agentPw.connect.resolveHeaders({
    path: "acme.connections.docs",
  }),
);
```

## What `connect.prepare(...)` Returns

`connect.prepare(...)` answers one question:

What should the app do next for this connection path and resource?

It returns one of:

- `ready`: a credential already exists at `path`
- `input_required`: a matching profile requires HTTP inputs before the connection can continue
- `options`: a list of possible OAuth routes

The decision order is:

1. exact-path stored credential
2. matching profile
3. if required profile HTTP inputs are missing, `input_required`
4. profile-backed OAuth or discovery-backed OAuth
5. unconfigured

This has two important consequences:

- manual HTTP input is represented by `input_required`, not by a `headers` option
- discovery only runs after profile HTTP requirements are satisfied or when no profile matches

The library's default recommendation is exposed as both:

- `prepared.options[0]`
- `prepared.resolution.option`

That means most apps can just take `prepared.options[0]` when they want the default path.

Each result also includes `resolution`, which explains what `agent.pw` decided:

- `canonicalResource`
- `source`: `profile`, `discovery`, or `null`
- `reason`
- `profilePath`
- `option`

## Handling OAuth Callbacks

When the provider redirects back:

```ts
const completed = await unwrap(
  agentPw.connect.completeOAuth({
    callbackUri: "https://app.example.com/oauth/callback?code=...&state=...",
  }),
);

console.log(completed.path);
console.log(completed.credential);
```

Pending OAuth state is readable through the same surface:

```ts
const flow = await unwrap(agentPw.connect.getFlow(flowId));
```

## Handling Upstream Auth Challenges

If you already have an upstream HTTP response and only need to know whether it was a Bearer challenge, use `connect.classifyResponse(...)`:

```ts
const challenge = await unwrap(
  agentPw.connect.classifyResponse({
    resource: "https://docs.example.com/mcp",
    response: upstreamResponse,
  }),
);

if (challenge.kind === "auth-required") {
  console.log("Prompt for auth", challenge.scopes);
}

if (challenge.kind === "step-up") {
  console.log("Prompt for broader scopes", challenge.scopes);
}
```

The `response` input can be a Fetch `Response` or a plain `{ status, headers }` object from another server framework.

## Profiles

Profiles are optional admin-side configuration for known providers, broken discovery, or required HTTP inputs.

When a known profile matches, `agent.pw` prefers that profile and skips generic discovery. Otherwise it falls back to resource discovery.

For details and examples, see [Credential Profiles](./credential-profiles.md).

## Next Docs

- [Reference](./reference.md)
- [Credential Profiles](./credential-profiles.md)
- [Architecture](./architecture.md)
- [Security Model](./security-model.md)
