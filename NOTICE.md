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

## security-guidance patterns — Apache-2.0

Copyright (c) Anthropic, PBC. and the security-guidance contributors
https://github.com/anthropics/claude-plugins-official

Licensed under the Apache License, Version 2.0. The full licence header is
retained at the top of `src/thot/guard/patterns.py`.

## Prime Agent — MIT

Copyright (c) 2025 Mario Zechner

The `SKILL.md` format Thot loads is the one shared by Hermes Agent and Prime
Agent, so skills written for either work here unmodified.
