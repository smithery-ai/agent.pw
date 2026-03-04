---
name: pr
description: Create a pull request, ensure the branch is up to date with main,
  watch CI, and fix failures until all checks pass. Use this skill whenever the
  user says "create a PR", "open a PR", "submit a PR", "/pr", "push and create
  a pull request", "get this merged", or any variation of wanting their current
  branch turned into a reviewed pull request. Also use when the user says "fix CI",
  "CI is failing", or "iterate until green" on an existing PR.
---

# /pr — Create a Pull Request

Open a PR for the current branch, keep it in sync with main, and iterate on CI failures until all checks are green.

## How to execute

Use the `Task` tool to spawn a **background subagent** (`run_in_background: true`, `subagent_type: "general-purpose"`) that performs all the steps below. This keeps the main conversation unblocked so the user can continue working.

Pass the subagent a prompt containing:
- The full instructions from the steps below.
- The current working directory.
- Any user-provided title, description, or base branch overrides.

After launching the subagent, immediately tell the user the PR workflow is running in the background and they'll be notified when it completes.

## Steps for the subagent

### 1. Sync with main

Rebasing before opening the PR prevents merge conflicts from blocking CI and keeps the commit history clean.

- `git fetch origin main`
- `git rebase origin/main`
- On merge conflicts:
  - Read what main changed in the conflicting files (`git show origin/main -- <file>`) so you understand the intent of both sides before resolving.
  - Resolve carefully — preserve intent from both sides. Never blindly accept one side.
  - `git add` resolved files, then `git rebase --continue`.
- If rebase gets stuck, `git rebase --abort` and fall back to `git merge origin/main`.

### 2. Prepare the branch

- Run `git status` (never `-uall`), `git diff`, and `git log main..HEAD --oneline` in parallel to understand the full picture.
- If there are uncommitted changes, stage and commit them.
- `git push -u origin HEAD`.

### 3. Create the PR

- If a PR already exists for this branch (`gh pr view`), skip to step 4.
- Derive a concise title (<70 chars) from the diff against main.
- Write a body using this structure:
  ```
  ## Summary
  - (3-5 bullets)

  ## Test plan
  - [ ] (checklist)
  ```
- `gh pr create --title "..." --body "$(cat <<'EOF' ... EOF)"`.
- If the user provided a title or description, use it verbatim.

### 4. Watch CI

- Poll with `gh run watch <RUN_ID> --exit-status` for each workflow, or use `gh pr checks <PR>` to check status.
- Don't use `--fail-fast` — it aborts on the first failure which may be an unrelated job.
- If all checks pass → report the PR URL and stop.

### 5. Fix failures and iterate

CI failures are common — the goal is to diagnose from logs rather than guessing.

- `gh pr checks <PR>` to identify the failing job(s) and run IDs.
- `gh run view <RUN_ID> --log-failed` to read the actual error.
- If the error is in the code, fix it, commit (never amend pushed commits), and push.
- If the error is environmental (flaky infra, transient DB issues), rerun the job: `gh run rerun <RUN_ID> --failed`.
- Return to step 4. Repeat up to 4 times.

## Rules

- Never force-push or amend published commits — except after a `git rebase`, where `--force-with-lease` is required and acceptable.
- Never skip hooks (`--no-verify`).
- Base branch is `main` unless told otherwise.
- Investigate ALL failing CI jobs, including e2e. If the failure is clearly environmental or unrelated to the PR changes, note that in the PR and move on — but don't silently ignore failures.
