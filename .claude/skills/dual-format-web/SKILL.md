---
name: dual-format-web
description: Design web pages and API responses that serve both humans and AI agents
  from the same URL. Use this skill when building landing pages, documentation, service
  pages, API endpoints, or any web-facing content. Also trigger on "agent-friendly",
  "machine-readable", "content negotiation", "llms.txt", "dual format", or when the
  user wants a page to work for both humans and AI agents.
---

# Dual-Format Web Design

Every URL should serve two audiences from the same address — humans get a rendered page, agents get structured data. The mechanism is HTTP content negotiation on the `Accept` header.

## Content Negotiation

Switch response format based on the `Accept` header:

- `text/html` (browsers) → rendered HTML page
- `application/json` → structured JSON for agents
- `text/markdown` → clean markdown for LLMs
- `*/*` without `text/html` (curl, agents) → default to the machine-readable format

The same URL, the same route handler — just a format branch. Never build separate `/api/` paths for what content negotiation solves.

Reference implementation in this codebase: `src/discovery.ts` (`wantsJson()`) and `src/index.ts` (root `/` and `/:service` routes).

## Inline LLM Instructions

Embed a bootstrap hint in every HTML page so agents that receive HTML know to re-request in a machine-readable format:

```html
<head>
  <script type="text/llms.txt">
  This page supports content negotiation.
  Re-request this URL with `Accept: application/json` for structured data
  or `Accept: text/markdown` for a markdown summary.
  </script>
</head>
```

Browsers ignore `<script>` tags with unrecognized types. Agents that parse raw HTML will find this instruction and switch to the optimized format on the next request. This is the bridge — it turns a blind HTML fetch into an informed negotiation.

For error pages and auth walls, the inline instruction should tell the agent what to do:

```html
<script type="text/llms.txt">
Authentication required. Re-request this URL with `Accept: application/json`
to receive a structured response with an auth_url you can present to the user.
</script>
```

## Structured JSON Responses

Agent-facing JSON should be self-describing and actionable:

- **`description`**: one-line summary of what this resource is
- **`quick_start`**: minimal steps to accomplish the most common task
- **`next_actions`**: HATEOAS-style links/templates so the agent knows what to do next — parameterized with `<required>` and `[--optional <value>]` syntax
- **`fix`** (on errors): plain-language remediation the agent can act on
- **`auth_url`** (on 401s): where to send the user to authenticate

Keep responses concise. Link to detail pages rather than inlining everything — agents have finite context windows.

## Site-Level Discovery

Serve `/llms.txt` at the site root — the `robots.txt` for AI. It should:

- Summarize what the site/service does in one paragraph
- Link to key resources (API docs, authentication, quickstart)
- State constraints (rate limits, required auth, supported formats)

Keep it under 50 lines. Agents will follow links for depth.

## HTML Page Design for Agents

Pages that agents may fetch as HTML (before they discover content negotiation) should degrade gracefully:

- **No JS-only content**: everything meaningful should be in the initial HTML response. Agents don't execute JavaScript.
- **Clear heading hierarchy**: agents use `<h1>`–`<h3>` to navigate and extract structure.
- **Explicit constraints**: state limits, required fields, and boundaries as text — not as form validation logic agents can't see.
- **Visible content**: no hidden tabs, collapsed accordions, or content behind "show more" buttons. If it matters, render it.
- **Facts over marketing**: agents need specifications, not persuasion. "Rate limit: 100 req/min" beats "blazing fast API."

## Error Responses

Errors should help agents self-recover:

```json
{
  "ok": false,
  "error": { "message": "Token expired", "code": "TOKEN_EXPIRED" },
  "fix": "Re-authenticate by directing the user to the auth_url below.",
  "auth_url": "https://example.com/auth/start?flow=abc",
  "next_actions": [
    { "action": "re-authenticate", "method": "GET", "url": "/auth/start" },
    { "action": "refresh-token", "method": "POST", "url": "/auth/refresh" }
  ]
}
```

A `fix` field with plain-language remediation is the difference between an agent that recovers and one that spins.
