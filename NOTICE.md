# NOTICE

Thot is a fusion of two programs. Most of what makes it useful was written
by someone else first; this file says exactly which parts, and what was done
to them.

Three kinds of provenance are distinguished, because they are not the same
thing and conflating them would be dishonest:

* **copied** — the file is upstream's, sometimes with named edits;
* **adapted** — the design is upstream's, the code is Thot's;
* **shared** — a format both programs read, invented by neither.

---

## Hermes Agent — MIT

Copyright (c) 2025 Nous Research · https://github.com/NousResearch/hermes-agent

### Copied

**Skill library** (`skills/`, `optional-skills/`) — the whole of Hermes's
`skills/` (82) and `optional-skills/` (117), file for file. Author, licence
and version fields in every `SKILL.md` frontmatter are preserved verbatim.

Two edits were made, both named here because they change what a reader sees:

1. workspace paths — `.hermes/plans/` became `.thot/plans/` and so on, so a
   skill writes where Thot actually looks. `skills/autonomous-ai-agents/hermes-agent/`
   is excluded from that rewrite: it documents Hermes itself, and rewriting
   its paths would turn documentation into fiction.
2. six skills were moved from `optional-skills/` into `skills/` because they
   are this program's subject matter: `web-pentest`, `oss-forensics`,
   `ast-grep`, `code-wiki`, `rest-graphql-debug`,
   `subagent-driven-development`.

Nothing was rewritten to hide its origin. Where a ported skill tells the
model to call a tool Thot does not have — `delegate_task` and friends — Thot
appends a note at read time saying which tools are missing and what to use
instead, rather than editing 89 files.

Several of those skills are themselves adaptations, credited in their own
frontmatter — notably `obra/superpowers` and `gsd-build/get-shit-done`.

**Skill guard** (`src/thot/guard/skill_guard.py`) — ported whole from
`tools/skills_guard.py`, ~1.1k lines, stdlib only, threat rules intact.
Two rules were widened rather than rewritten: what protected `~/.hermes/`
and `.hermes/config.yaml` now also protects `~/.thot/`. `builtin` was added
as a trust level alongside Hermes's `official`, meaning the same thing.

**Security patterns** (`src/thot/guard/patterns.py`) — ported unchanged from
`plugins/security-guidance/patterns.py`. That file is itself a verbatim fork
of Anthropic's `claude-plugins-official` under Apache-2.0 (see below). Thot
adds two uses Hermes does not have: a repository-wide audit sweep, and
masking of Python string literals and comments before matching.

**MCP catalogue** (`mcp-catalog/`) — Hermes's `optional-mcps/`, twenty
manifests copied unchanged and read in their original format.

### Adapted

**Session state** (`src/thot/state/`) — the design of `hermes_state.py` and
its four companion modules, ~16k lines reduced to ~700. What was kept is
what production paid for: additive schema, an FTS mirror maintained by
trigger, FTS5 probed rather than assumed, WAL with a silent fallback,
compression chains through `parent_id`, and imports that remap instead of
overwriting. What was dropped is everything a gateway needs and a local
audit tool does not — CJK extension loading, cross-process repair ledgers,
macOS checkpoint barriers, compression locks. No upstream code copied.

**Plugin system** (`src/thot/plugins/`) — the manifest layout and the
isolate-every-callback dispatch are adapted from `hermes_cli/plugins.py`.
Narrowed from dozens of hooks to five. No upstream code copied.

**Gateway** (`src/thot/gateway/`) — the platform-adapter shape from
`plugins/platforms/*`, narrowed to `send` and `poll`, with Hermes's own
environment-variable names so a machine configured for Hermes needs nothing
new. Five channels of its twenty-two. Hermes's `ALLOW_ALL_USERS` escape
hatch is deliberately not ported: this gateway can start audits and record
verdicts. No upstream code copied.

**Memory backends** (`src/thot/memory/remote.py`) — the self-hosted mem0
contract exactly as `plugins/memory/mem0/_backend.py` speaks it
(`X-API-Key`, `POST /memories`, `POST /search`, `DELETE /memories/{id}`),
so a mem0 server already running for Hermes serves Thot too. Thot stores
one memory per verdict with `infer` off, because mem0's inference
paraphrases and a paraphrased verdict stops matching its finding. No
upstream code copied.

**Supply-chain audit** (`src/thot/supply/`) — the OSV.dev usage from
`hermes_cli/security_audit.py` (querybatch, per-advisory detail, severity
mapping, parallel fetch) and the malware pre-check from
`tools/osv_check.py`, including its cache-the-verdict-not-the-failure rule,
whose comment records 779k DNS queries in 16 hours from an uncached retry
loop. The surface is moved: Hermes scans its own venv, plugins and MCP
config because it audits the machine it runs on; Thot scans the repository
under audit, plus the MCP servers the user executes. No upstream code
copied.

**Sandbox** (`src/thot/sandbox/`) — the container hardening from
`tools/environments/docker.py`: `--cap-drop ALL`,
`--security-opt no-new-privileges`, nosuid tmpfs, pids/memory/CPU limits.
Two of Hermes's eleven environments are kept, local and docker, because
those are the two that answer "is this code running as me". The lifecycle
machinery — file sync, long-lived containers, Modal, Daytona, Vercel,
Singularity, SSH — is not ported: Thot needs one command to run and the
container to be gone. No upstream code copied.

**Local observability** (`plugins/audit-log/`) — the useful half of Hermes's
`plugins/observability/*`, without the vendor: a JSONL journal on this
machine instead of a Langfuse or Datadog client.

**Scheduled audits** (`src/thot/schedule/`) — the job shape is adapted from
`cron/jobs.py`. The diff-only reporting is Thot's own. No upstream code copied.

**Memory** (`src/thot/memory/`) — the provider contract is adapted from
`agent/memory_provider.py`, narrowed from conversational recall to durable
audit verdicts. No upstream code copied.

**Home directory** (`src/thot/paths.py`) — `THOT_HOME` mirrors
`hermes_constants.get_hermes_home`.

---

## Prime Agent — MIT

Copyright (c) 2025 Mario Zechner

Prime is TypeScript; nothing here is a copy. These are the ideas that
survived translation into Python.

### Adapted

**Goals** (`src/thot/state/goals.py`) — the model in `core/goals.ts`:
objective, status, token budget, and running out of budget being a state
(`budget_limited`) rather than an error. Thot's version is scoped to a
repository rather than to a thread.

**Custom commands** (`src/thot/commands/`) — the prompt-template mechanism
in `core/prompt-templates.ts`, including its substitution grammar exactly:
`$1`, `$@`, `$ARGUMENTS`, `${@:N}`, `${@:N:L}`, and arguments never being
re-expanded.

**Compaction** (`SessionStore.branch`) — `/compact` closing a session on a
summary and continuing in a linked child, so context is lost and evidence
is not.

**skill-creator** (`skills/software-development/skill-creator/`) — Prime's
skill of the same name, rewritten for Thot's storage layout and trust model.

**Memory provider discovery** (`src/thot/memory/factory.py`,
`layered.py`) — the several-sources-one-active idea from
`plugins/memory/__init__.py`. Hermes orders its sources bundled-first so a
directory dropped into a working tree cannot silently redirect the agent's
memory; Thot orders its layers repository-first for the mirror-image
reason — here the working tree is the reviewed artefact and the local
store is the scratch pad. Writes still land locally, and publishing to the
committed file is a separate act.

### Shared

The `SKILL.md` format Thot loads is the one Hermes Agent and Prime Agent
both read — the [Agent Skills standard](https://agentskills.io/specification).
A skill written for either program loads here unmodified.

---

## security-guidance patterns — Apache-2.0

Copyright (c) Anthropic, PBC. and the security-guidance contributors
https://github.com/anthropics/claude-plugins-official

Licensed under the Apache License, Version 2.0. The full licence header is
retained at the top of `src/thot/guard/patterns.py`.
