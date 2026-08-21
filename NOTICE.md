# NOTICE

Thot incorporates work from two projects, with thanks.

## Hermes Agent — MIT

Copyright (c) 2025 Nous Research · https://github.com/NousResearch/hermes-agent

**Skills** (`skills/software-development/`, `skills/review/`) — ported from
`skills/software-development/`, `skills/github/` and `skills/devops/`.
Adapted for Thot: `.hermes/` paths and tool names now refer to Thot. Author
attribution in each `SKILL.md` frontmatter is preserved verbatim.

Several of those skills are themselves adaptations, credited in their own
frontmatter — notably `obra/superpowers` and `gsd-build/get-shit-done`.

**Security patterns** (`src/thot/guard/patterns.py`) — ported unchanged from
`plugins/security-guidance/patterns.py`. That file is itself a verbatim fork
of Anthropic's `claude-plugins-official` under Apache-2.0 (see below). Thot
adds two uses Hermes does not have: a repository-wide audit sweep, and
masking of Python string literals and comments before matching.

**Plugin system** (`src/thot/plugins/`) — the manifest layout and the
isolate-every-callback dispatch are adapted from `hermes_cli/plugins.py`.
Narrowed from dozens of hooks to five; no upstream code copied.

**Scheduled audits** (`src/thot/schedule/`) — the job shape is adapted from
`cron/jobs.py`. The diff-only reporting is Thot's own; no upstream code copied.

**Memory** (`src/thot/memory/`) — the provider contract is adapted from
`agent/memory_provider.py`, narrowed from conversational recall to durable
audit verdicts. No upstream code copied.

## security-guidance patterns — Apache-2.0

Copyright (c) Anthropic, PBC. and the security-guidance contributors
https://github.com/anthropics/claude-plugins-official

Licensed under the Apache License, Version 2.0. The full licence header is
retained at the top of `src/thot/guard/patterns.py`.

## Prime Agent — MIT

Copyright (c) 2025 Mario Zechner

The `SKILL.md` format Thot loads is the one shared by Hermes Agent and Prime
Agent, so skills written for either work here unmodified.
