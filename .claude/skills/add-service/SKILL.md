---
name: add-service
description: Register a new API service in agent.pw by researching its auth docs and
  calling the service API. Use this skill whenever the user says "add a service",
  "register <hostname>", "set up <api name>", "agent.pw service add", or any variation
  of wanting to connect a new API service to agent.pw. Also trigger when the user
  provides an API hostname and wants it configured.
---

# Add a Service to agent.pw

The user wants to register an API service so agent.pw knows how to authenticate requests to it. The argument is typically a hostname (e.g., `api.linear.app`).

## Steps

1. **Search the web** for the service's API documentation. Find:
   - How API requests are authenticated (API keys, bearer tokens, OAuth)
   - The API's base URL and docs URL

2. **Determine auth schemes.** Build an array of auth scheme objects. Each scheme is one of:

   API Key — a static key sent in a specific header or query param:
   ```json
   { "type": "apiKey", "in": "header", "name": "X-Api-Key" }
   ```
   `in` is `"header"`, `"query"`, or `"cookie"`. `name` is the header/param name.

   HTTP — bearer token or basic auth:
   ```json
   { "type": "http", "scheme": "bearer" }
   ```
   `scheme` is `"bearer"` or `"basic"`.

   OAuth 2.0 — authorization code flow:
   ```json
   { "type": "oauth2", "authorizeUrl": "https://...", "tokenUrl": "https://...", "scopes": "read write" }
   ```

   Most APIs support multiple schemes. List all of them. Put the simplest scheme first.

3. **Write the service JSON** to a temp file:

   ```json
   {
     "baseUrl": "https://<hostname>",
     "displayName": "Human Name",
     "description": "One-line description",
     "authSchemes": [],
     "docsUrl": "https://..."
   }
   ```
   - `baseUrl` (required): usually `https://<hostname>`
   - `displayName`: human-readable name (e.g., "Linear", "GitHub")
   - `description`: one-line description
   - `authSchemes`: array from step 2
   - `docsUrl`: link to the API documentation

4. **Register the service** via CLI:

   ```bash
   npx agent.pw service add <hostname> --file /tmp/service.json
   ```

5. **Verify** it was registered:

   ```bash
   npx agent.pw service get <hostname>
   ```

6. **Tell the user** the service is registered and they can add a credential with `npx agent.pw cred add <hostname>`.

## Examples

GitHub:
```json
{
  "baseUrl": "https://api.github.com",
  "displayName": "GitHub",
  "description": "Code hosting and collaboration",
  "authSchemes": [
    { "type": "http", "scheme": "bearer" },
    { "type": "oauth2", "authorizeUrl": "https://github.com/login/oauth/authorize", "tokenUrl": "https://github.com/login/oauth/access_token", "scopes": "repo read:user" }
  ],
  "docsUrl": "https://docs.github.com/en/rest"
}
```

Stripe:
```json
{
  "baseUrl": "https://api.stripe.com",
  "displayName": "Stripe",
  "description": "Payment processing",
  "authSchemes": [
    { "type": "http", "scheme": "bearer" }
  ],
  "docsUrl": "https://stripe.com/docs/api"
}
```

Linear:
```json
{
  "baseUrl": "https://api.linear.app",
  "displayName": "Linear",
  "description": "Project management and issue tracking",
  "authSchemes": [
    { "type": "apiKey", "in": "header", "name": "Authorization" },
    { "type": "oauth2", "authorizeUrl": "https://linear.app/oauth/authorize", "tokenUrl": "https://api.linear.app/oauth/token", "scopes": "read" }
  ],
  "docsUrl": "https://developers.linear.dev/docs"
}
```
