---
name: thot
description: The repository's map — files, symbols, callers, and audited taint paths — computed offline by Thot and served over MCP. Use it before grepping: the answer is already there, and it costs no tokens.
---

# Thot

Thot has already read this repository. It indexed every file into an AST, built
the call graph, and ran its taint analysis — offline, deterministically, before
you asked anything. These tools hand you that map.

Reach for them **before** opening files. Finding a symbol by reading the tree
costs a dozen tool calls and a lot of context; `find_symbol` costs one, and it
answers with the exact file and line range.

## Setup

`thot fusion wire` writes the connection into this agent's settings, and
`thot mcp serve --http` runs the server it points at. If a call raises
`NotEnabled`, the credential is missing — run `thot fusion wire` again rather
than asking anyone to set environment variables.

## Usage

The tool set is defined by the server. Discover before you call:

```python
import thot_map

for tool in await thot_map.list_tools():
    print(tool["name"], "-", tool["description"])
```

The six that are always there:

```python
# Every file in scope. With a glob, only the ones that match.
await thot_map.code_map(root="/path/to/project", pattern="*/engine/*.py")

# Where a function or class is defined: file, line range, parameters.
await thot_map.find_symbol(root="/path/to/project", name="run_audit")

# Who calls it, what it calls, and how far it sits from an entry point.
await thot_map.callers(root="/path/to/project", symbol="run_command")

# The taint paths Thot proved, source to sink, with severity.
await thot_map.audit(root="/path/to/project")

# The methods Thot ships: audit, debugging, TDD, review, planning.
await thot_map.skills()
await thot_map.skill(name="systematic-debugging")
```

`root` is an absolute path and it is not optional in practice: the server is
started from a configuration directory, not from the project, so it cannot
guess which repository you mean. Pass the one you are working in.
