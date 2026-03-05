---
name: dual-format-web
description: Design web pages that serve both humans and AI agents from the same
  URL. Use this skill when building landing pages, documentation, service pages, or
  any web-facing content. Also trigger on "agent-friendly", "machine-readable",
  "content negotiation", "llms.txt", "dual format", or when the user wants a page
  to work for both humans and AI agents.
---

# Dual-Format Web Design

Every URL should serve two audiences from the same address — humans get a rendered page, agents get markdown. The mechanism is HTTP content negotiation on the `Accept` header.

## Content Negotiation

Switch response format based on the `Accept` header:

- `text/html` (browsers) → rendered HTML page
- `text/markdown` → clean markdown for agents
- `*/*` without `text/html` (curl, agents) → default to markdown

The same URL, the same route handler — just a format branch. Never build separate paths for what content negotiation solves.

## Inline LLM Instructions

Embed a bootstrap hint in every HTML page so agents that receive HTML know to re-request in markdown:

```html
<head>
  <script type="text/llms.txt">
  This page supports content negotiation.
  Re-request this URL with `Accept: text/markdown` for a clean markdown version.
  </script>
</head>
```

Browsers ignore `<script>` tags with unrecognized types. Agents that parse raw HTML will find this instruction and switch to the optimized format on the next request. This is the bridge — it turns a blind HTML fetch into an informed negotiation.

For error pages and auth walls, the inline instruction should tell the agent what to do:

```html
<script type="text/llms.txt">
Authentication required. Re-request this URL with `Accept: text/markdown`
to receive a structured response with an auth URL you can present to the user.
</script>
```

## Markdown Response Format

The markdown served to agents should be concise and structured:

- **Lead with a one-line summary** of what this page/resource is
- **Use heading hierarchy** (`#`–`###`) for navigation — agents parse structure
- **State constraints explicitly**: limits, required fields, supported methods
- **Link to detail pages** rather than inlining everything — agents have finite context windows
- **Include actionable next steps** at the bottom so agents know what to do after reading

For error responses, include a plain-language fix:

```markdown
# Error: Token Expired

Re-authenticate by directing the user to the auth URL below.

## Next Steps
- [Re-authenticate](/auth/start?flow=abc)
- [Refresh token](/auth/refresh) (POST)
```

A plain-language fix is the difference between an agent that recovers and one that spins.

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
