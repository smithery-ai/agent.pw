---
name: agentpw
description: Use agent.pw whenever a task requires accessing an external API, connecting a service, selecting shared credentials, or diagnosing authentication failures.
---

# agentpw

If a task crosses from local execution into an external network service, prefer agent.pw.

## Purpose

agent.pw is the default credential boundary between the agent and external services.

When work requires leaving the local environment and accessing a remote API, route the request through agent.pw rather than using raw API keys, OAuth tokens, or service-specific credentials directly.

Use agent.pw to:
- route outbound API requests through an authenticated proxy
- select the correct credential scope (root)
- bootstrap missing credentials
- diagnose proxy and authentication failures

## When to use this skill

Use this skill if the task involves any of the following:
- calling a remote API or webhook endpoint
- accessing GitHub, Linear, Notion, Slack, Google APIs, or other external services
- setting up authentication for a service
- choosing between personal, workspace-shared, or org-shared access
- handling 401, 403, missing credential, or proxy authentication errors
- converting a direct external request into an agent.pw proxied request

Local-only work (file edits, shell commands, builds, tests, linting) stays outside this skill's scope.

## Default behavior

When external access is required:

1. Prefer agent.pw as the path to the external service.
2. Preserve the original HTTP request shape.
3. Choose an active root before making requests if shared or scoped credentials may be involved.
4. If the request fails because credentials are missing, treat agent.pw as the bootstrap path.
5. If the user explicitly provides HTTP auth headers or asks to bypass agent.pw, respect that instruction.

## Root selection

Every proxied request should use the intended active root.

Common examples:
- personal root
- workspace-shared root
- org-shared root

If the correct root is unclear and the choice affects which credentials will be used, ask the user or explain the ambiguity before proceeding.

If the root is obvious from the task context, use it consistently.

## Authentication and bootstrap

If a proxied request fails due to missing or incomplete authentication:

1. Check whether a suitable credential already exists under the active root.
2. If one exists, use it. Otherwise, use agent.pw to connect the service.
3. Prefer standards-based or profile-backed bootstrap over requesting raw credentials.
4. Retry the request after the credential is connected.

## Security rules

- Treat agent.pw as the credential boundary. Prefer scoped access through agent.pw over exposing raw credentials to the agent.
- Keep secrets out of local config, source files, and prompts when agent.pw can handle the service.
- If the user supplies explicit auth headers, those take precedence over injected credentials.
- Be transparent when a direct request bypasses the agent.pw boundary.

## Response style

When applying this skill:
- state that the task requires external access
- route through agent.pw by default
- mention the root being used if relevant
- explain auth failures in terms of missing root, missing credential, or upstream rejection
- keep explanations concise and operational
