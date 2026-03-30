# agent.pw

[![npm version](https://img.shields.io/npm/v/agent.pw)](https://www.npmjs.com/package/agent.pw)

Build your own 1Password for AI agents. Securely store credentials and use them anywhere.

* **Encrypted.** AES-GCM at rest. Agents only see resolved headers, never raw secrets.
* **OAuth.** Full flow with PKCE, token refresh, and dynamic client registration.
* **API keys.** Same API for bearer tokens, custom headers, any header-based auth.
* **Multi-tenant.** Path-scoped credentials with subtree queries and authorization rules.
* **Guided setup.** Define profiles for services. `prepare()` tells your app what to ask the user.
* **Local-first.** Ships with PGlite. No Postgres needed for dev.

## Quick start

### Using Agent Skills

```sh
npx skills add https://github.com/smithery-ai/agent.pw
```

Then run:

```
/setup-agentpw
```

### Manual

```sh
npm install agent.pw
```

```ts
import { createAgentPw } from "agent.pw";
import { createLocalDb, bootstrapLocalSchema } from "agent.pw/sql";
import { createInMemoryFlowStore } from "agent.pw/oauth";
import { unwrap } from "okay-error";

const db = unwrap(await createLocalDb("./agentpw-data"));
unwrap(await bootstrapLocalSchema(db));

const pw = unwrap(
  await createAgentPw({
    db,
    encryptionKey: process.env.AGENTPW_KEY!, // 32 bytes, base64
    flowStore: createInMemoryFlowStore(),
  }),
);

// store a credential
await unwrap(
  pw.connect.setHeaders({
    path: "acme.connections.resend",
    resource: "https://api.resend.com/",
    headers: { Authorization: "Bearer re_123" },
  }),
);

// resolve from anywhere — refresh handled automatically
const headers = unwrap(
  await pw.connect.resolveHeaders({ path: "acme.connections.resend" }),
);
// => { Authorization: "Bearer re_123" }

await fetch("https://api.resend.com/emails", { headers });
```

Generate an encryption key:

```sh
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

## Connect flow

`connect.prepare()` tells your app what to do next for a given connection:

```ts
const prepared = unwrap(
  await pw.connect.prepare({
    path: "acme.connections.github",
    resource: "https://api.github.com/",
  }),
);

if (prepared.kind === "ready") {
  // credential exists — use prepared.headers
  return prepared.headers;
}

// no credential yet — present auth options to the user
for (const option of prepared.options) {
  if (option.kind === "oauth") {
    const session = unwrap(
      await pw.connect.startOAuth({
        path: "acme.connections.github",
        option,
        redirectUri: "https://app.example.com/callback",
      }),
    );
    return Response.redirect(session.authorizationUrl, 302);
  }

  if (option.kind === "headers") {
    // collect API key from user, then:
    await unwrap(
      pw.connect.setHeaders({
        path: "acme.connections.github",
        resource: "https://api.github.com/",
        headers: { Authorization: `Bearer ${token}` },
      }),
    );
  }
}
```

Complete an OAuth flow when the user returns:

```ts
const completed = unwrap(
  await pw.connect.completeOAuth({
    callbackUri: "https://app.example.com/callback?code=...&state=...",
  }),
);
```

## Profiles

Define auth configuration for known services. `prepare()` uses these to return the right options:

```ts
// API key service
await pw.profiles.put("resend", {
  resourcePatterns: ["https://api.resend.com*"],
  displayName: "Resend",
  auth: {
    kind: "headers",
    label: "API key",
    fields: [{ name: "Authorization", prefix: "Bearer ", secret: true }],
  },
});

// OAuth service
await pw.profiles.put("github", {
  resourcePatterns: ["https://api.github.com/*"],
  displayName: "GitHub",
  auth: {
    kind: "oauth",
    authorizationUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    clientId: process.env.GITHUB_CLIENT_ID!,
    clientSecret: process.env.GITHUB_CLIENT_SECRET!,
    scopes: "repo user",
  },
});
```

Profiles are path-scoped — set global defaults and override per org or workspace. See [credential profiles](./docs/credential-profiles.md) for matching rules.

## Scoped API

Enforce path-based authorization:

```ts
const scoped = pw.scope({
  rights: [{ action: "credential.use", root: "acme" }],
});

// ✓ path is under "acme"
await scoped.connect.resolveHeaders({ path: "acme.connections.github" });

// ✗ blocked — outside granted root
await scoped.connect.resolveHeaders({ path: "other.connections.github" });
```

## Error handling

Every function returns a `Result` from [okay-error](https://www.npmjs.com/package/okay-error). The examples use `unwrap()` which throws on errors. In production:

```ts
const result = await pw.connect.resolveHeaders({
  path: "acme.connections.github",
});

if (!result.ok) {
  console.error(result.error);
  return;
}

const headers = result.value;
```

## Database

**Development** — PGlite, no external database:

```ts
import { createLocalDb, bootstrapLocalSchema } from "agent.pw/sql";
const db = unwrap(await createLocalDb("./data"));
unwrap(await bootstrapLocalSchema(db));
```

**Production** — PostgreSQL:

```ts
import { createDb } from "agent.pw/sql";
const db = unwrap(createDb(process.env.DATABASE_URL!));
```

For production, you own migrations. Tables can be namespaced:

```ts
const sql = { schema: "platform", tablePrefix: "agentpw_" };
const db = unwrap(createDb(process.env.DATABASE_URL!, { sql }));
const pw = unwrap(await createAgentPw({ db, sql, encryptionKey, flowStore }));
```

## Docs

- [Architecture](./docs/architecture.md)
- [Credential Profiles](./docs/credential-profiles.md)
- [Security Model](./docs/security-model.md)

## License

[MIT](./LICENSE.md)
