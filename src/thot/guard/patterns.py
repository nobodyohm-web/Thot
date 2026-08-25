"""
Regex-based security pattern definitions for the security-guidance plugin.

Pure data + one pure helper. No env-var reads, no I/O — kept side-effect-free
so it can be imported in isolation.

Forked verbatim from Anthropic's claude-plugins-official repository
(plugins/security-guidance/hooks/patterns.py) under the Apache License 2.0:

    https://github.com/anthropics/claude-plugins-official

  Copyright (c) Anthropic, PBC. and the security-guidance contributors
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

Modifications by NousResearch for the Hermes Agent plugin port:
  - none to the pattern data itself; this file is byte-for-byte the upstream
    patterns.py at commit 0bde168 (2026-05-26). Hermes-side wiring lives in
    __init__.py.

Ported into Thot from Hermes Agent (MIT, Copyright (c) 2025 Nous Research):
  - the upstream rules are unchanged. Thot uses them for two things Hermes
    does not: an audit sweep over the whole repository, and a guard on the
    agent's own writes. The wiring lives in scanner.py and guard.py.
  - two rules are added at the end, `hardcoded_credential` and
    `hardcoded_secret_assignment`. Upstream's catalogue is written for a
    model mid-edit, where a leaked key is not the concern; a sweep over a
    repository is exactly where it is.
"""
from enum import IntEnum


_JS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte")
_PY_EXTS = (".py", ".pyi", ".ipynb")
_DOC_EXTS = (".md", ".mdx", ".txt", ".rst", ".json", ".yaml", ".yml")


_UNSAFE_DESERIALIZATION_REMINDER = """⚠️ Security Warning: Loading pickle data (or equivalents: cPickle, cloudpickle, dill, marshal, shelve, joblib, pandas.read_pickle, numpy with allow_pickle=True) from untrusted sources allows arbitrary code execution.

For simple data, prefer JSON or msgspec. For typed objects, prefer a schema-validated deserializer (msgspec.Struct, pydantic, marshmallow) that constructs only declared types.

If this is safe or is explicitly needed, briefly document that in a comment before continuing."""

_UNSAFE_YAML_LOAD_REMINDER = """⚠️ Security Warning: yaml.load() / yaml.unsafe_load() execute arbitrary Python via !!python/object tags.

Use yaml.safe_load() if the file only contains simple data structures (dicts, lists, strings, numbers). If you need typed objects, parse with safe_load and validate the result against a schema (pydantic, msgspec, marshmallow) — never use a custom Loader that constructs arbitrary types."""

_UNSAFE_TORCH_LOAD_REMINDER = """⚠️ Security Warning: torch.load() defaults to weights_only=False, which unpickles arbitrary Python objects and allows arbitrary code execution.

If the file only contains tensors and simple data structures, pass weights_only=True (or set TORCH_FORCE_WEIGHTS_ONLY_LOAD=1)."""

# Security patterns configuration
SECURITY_PATTERNS = [
    {
        "ruleName": "github_actions_workflow",
        "path_check": lambda path: ".github/workflows/" in path
        and (path.endswith(".yml") or path.endswith(".yaml")),
        "reminder": """⚠️ Security Warning: You are editing a GitHub Actions workflow file. Be aware of these security risks:

1. **Command Injection**: Never use untrusted input (like issue titles, PR descriptions, commit messages) directly in run: commands without proper escaping
2. **Use environment variables**: Instead of ${{ github.event.issue.title }}, use env: with proper quoting
3. **Review the guide**: https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/

Example of UNSAFE pattern to avoid:
run: echo "${{ github.event.issue.title }}"

Example of SAFE pattern:
env:
  TITLE: ${{ github.event.issue.title }}
run: echo "$TITLE"

Other risky inputs to be careful with:
- github.event.issue.body
- github.event.pull_request.title
- github.event.pull_request.body
- github.event.comment.body
- github.event.review.body
- github.event.review_comment.body
- github.event.pages.*.page_name
- github.event.commits.*.message
- github.event.head_commit.message
- github.event.head_commit.author.email
- github.event.head_commit.author.name
- github.event.commits.*.author.email
- github.event.commits.*.author.name
- github.event.pull_request.head.ref
- github.event.pull_request.head.label
- github.event.pull_request.head.repo.default_branch
- github.event.client_payload.* (repository_dispatch events — attacker can set any field)

4. **Ref injection**: Never use untrusted input in `ref:` parameters of `actions/checkout`. For `client_payload.pr_number`, validate it matches `^[0-9]+$` before using in `ref: refs/pull/${{ ... }}/head`
- github.head_ref""",
    },
    {
        "ruleName": "child_process_exec",
        # Gate to JS/TS files — bare `exec(` otherwise fires on Python's
        # exec() and on prose/docstrings mentioning exec.
        "path_filter": lambda p: p.endswith(_JS_EXTS),
        "substrings": ["child_process.exec", "execSync("],
        "regex": r"(?<![a-zA-Z0-9_\.])exec\(",
        "reminder": """⚠️ Security Warning: Using child_process.exec() can lead to command injection vulnerabilities.

exec() runs the command string through a shell, so any user input interpolated into it can inject arbitrary commands. Prefer child_process.execFile() (or spawn()) with an argument array instead of building a shell string.

Instead of:
  exec(`command ${userInput}`)

Use:
  import { execFile } from 'node:child_process'
  execFile('command', [userInput], callback)

Why execFile/spawn with an argument array is safer:
- No shell is involved, so shell metacharacters in arguments are not interpreted
- Arguments are passed directly to the program rather than interpolated into a command string

Only use exec() if you absolutely need shell features and the input is guaranteed to be safe.""",
    },
    {
        "ruleName": "new_function_injection",
        "substrings": ["new Function"],
        "reminder": "\u26a0\ufe0f Security Warning: Using new Function() with string interpolation is a CODE INJECTION vulnerability. If any variable is concatenated or interpolated into the function body string, an attacker controlling that variable can execute arbitrary code. Use safe alternatives: for property access use obj[key] or array.reduce((o, k) => o[k], root); for computation use a safe expression parser. NEVER interpolate untrusted strings into new Function() bodies.",
    },
    {
        "ruleName": "eval_injection",
        # Lookbehind excludes `.` so method calls like PyTorch model.eval(),
        # redis.eval(), spec.eval() don't match. Skip doc/prose files.
        "path_filter": lambda p: not p.endswith(_DOC_EXTS),
        "regex": r"(?<![a-zA-Z0-9_\.])eval\(",
        "reminder": "⚠️ Security Warning: eval() executes arbitrary code and is a major security risk. Use JSON.parse() for data, ast.literal_eval() for Python literals, or a safe expression parser. If this is safe or is explicitly needed, briefly document that in a comment before continuing.",
    },
    {
        "ruleName": "react_dangerously_set_html",
        # Same reason as `tls_verification_disabled` below.
        "path_filter": lambda p: not p.endswith(_DOC_EXTS),
        "substrings": ["dangerouslySetInnerHTML"],
        "reminder": "⚠️ Security Warning: dangerouslySetInnerHTML can lead to XSS vulnerabilities if used with untrusted content. Ensure all content is properly sanitized using an HTML sanitizer library like DOMPurify, or use safe alternatives.",
    },
    {
        "ruleName": "document_write_xss",
        "substrings": ["document.write"],
        "reminder": "⚠️ Security Warning: document.write() can be exploited for XSS attacks and has performance issues. Use DOM manipulation methods like createElement() and appendChild() instead.",
    },
    {
        "ruleName": "innerHTML_xss",
        "substrings": [".innerHTML =", ".innerHTML="],
        "reminder": "⚠️ Security Warning: Setting innerHTML with untrusted content can lead to XSS vulnerabilities. Use textContent for plain text or safe DOM methods for HTML content. If you need HTML support, consider using an HTML sanitizer library such as DOMPurify.",
    },
    {
        "ruleName": "pickle_deserialization",
        # Match deserialization only (load/loads/Unpickler). pickle.dump is
        # not the RCE surface. `pkl_load` needs a word boundary so similarly
        # named safe loaders don't match.
        "path_filter": lambda p: p.endswith(_PY_EXTS),
        "regex": r"(?<![a-zA-Z0-9_])pickle\.(loads?|Unpickler)\b|(?<![a-zA-Z0-9_])pkl_load\(",
        "reminder": _UNSAFE_DESERIALIZATION_REMINDER,
    },
    {
        "ruleName": "os_system_injection",
        "path_filter": lambda p: p.endswith(_PY_EXTS),
        "regex": r"\bos\.system\s*\(",
        "substrings": ["from os import system"],
        "reminder": "⚠️ Security Warning: os.system() runs a shell and is a command-injection sink. Use subprocess.run([...]) with a list of arguments instead. If this is safe or is explicitly needed, briefly document that in a comment before continuing.",
    },
    {
        "ruleName": "python_subprocess_shell",
        "regex": r"subprocess\.(?:run|call|Popen|check_output|check_call)\(.*shell\s*=\s*True",
        "reminder": """⚠️ Security Warning: Using subprocess with shell=True enables command injection.

UNSAFE:
  subprocess.run(f"ls {user_input}", shell=True)
  subprocess.call("grep " + pattern, shell=True)

SAFE - pass arguments as a list without shell:
  subprocess.run(["ls", user_input])
  subprocess.call(["grep", pattern])

When arguments are passed as a list without shell=True, special characters cannot be interpreted as shell metacharacters.""",
    },
    # =====================================================================
    # Go-specific security patterns
    # =====================================================================
    {
        "ruleName": "go_exec_shell_injection",
        # Detect exec.Command with shell invocation (sh, bash, /bin/sh, /bin/bash)
        "regex": r'exec\.Command\(\s*"(?:sh|bash|/bin/sh|/bin/bash)"',
        "reminder": """⚠️ Security Warning: Using exec.Command with a shell interpreter (sh/bash) enables command injection.

UNSAFE:
  exec.Command("sh", "-c", "ping -c 1 " + host)
  exec.Command("bash", "-c", fmt.Sprintf("df -h %s", path))

SAFE - pass arguments directly without a shell:
  exec.Command("ping", "-c", "1", host)
  exec.Command("df", "-h", path)

When arguments are passed directly (not through a shell), special characters in user input cannot be interpreted as shell metacharacters. This prevents command injection entirely.

Additionally, validate user inputs:
- For hostnames/IPs: use net.ParseIP() or a hostname regex
- For file paths: use filepath.Clean() and verify the result is within an allowed directory
- For numeric values: parse to int/float first""",
    },
    {
        "ruleName": "unsafe_yaml_load",
        "regex": r"\byaml\.load\s*\((?![^)\n]{0,80}\bSafe)",
        "reminder": _UNSAFE_YAML_LOAD_REMINDER,
    },
    {
        "ruleName": "node_createcipher_no_iv",
        "regex": r"\bcrypto\.(createCipher|createDecipher)\b",
        "reminder": "⚠️ Security Warning: Use crypto.createCipheriv() / createDecipheriv(). createCipher was removed in Node 22 and derives the key insecurely (no IV, MD5-based KDF).",
    },
    {
        "ruleName": "aes_ecb_mode",
        "regex": r"\bAES\.MODE_ECB\b|\bmodes\.ECB\s*\(|[\x22\x27]aes-\d+-ecb[\x22\x27]",
        "reminder": "⚠️ Security Warning: Use AES-GCM or AES-CBC with HMAC. ECB mode leaks plaintext structure (identical blocks encrypt to identical ciphertext).",
    },
    {
        "ruleName": "tls_verification_disabled",
        # Prose naming the pattern is not the pattern: the plugin that warns
        # against `verify=False` was reported for containing `verify=False`.
        "path_filter": lambda p: not p.endswith(_DOC_EXTS),
        "regex": r"\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\x22\x27]?0|ssl\._create_unverified_context|check_hostname\s*=\s*False",
        "reminder": "⚠️ Security Warning: Don't disable TLS verification. This allows MITM attacks. For self-signed dev certs, add the CA to your trust store or use a properly-issued cert.",
    },
    {
        "ruleName": "marshal_loads",
        "regex": r"\bmarshal\.loads?\s*\(",
        "reminder": _UNSAFE_DESERIALIZATION_REMINDER,
    },
    {
        "ruleName": "shelve_open",
        "regex": r"\bshelve\.open\s*\(",
        "reminder": _UNSAFE_DESERIALIZATION_REMINDER,
    },
    {
        "ruleName": "xml_unsafe_parse",
        # Measured on 100 labelled XXE cases: this rule scored -100 % — it
        # missed every vulnerable one and fired on every safe one. Two
        # reasons, both here.
        #
        # `\bElementTree\.` matched inside `defusedxml.ElementTree.fromstring`,
        # so the rule flagged the library whose only purpose is to prevent
        # XXE — the very remedy its own reminder recommends. Hence the
        # lookbehind. (`from defusedxml import ElementTree as ET` still slips
        # through: the alias is resolved at import, which a line-wise regex
        # cannot see.)
        #
        # And `lxml` was absent from the alternation altogether, though it is
        # the XML library most Python code actually uses. Only the shapes
        # that disable a defence outright are matched — `resolve_entities=True`
        # and `no_network=False` — because a bare `etree.parse` depends on a
        # default this rule cannot read from one line.
        "regex": r"(?<!defusedxml\.)\b(xml\.etree\.ElementTree|ElementTree|ET)\.(parse|fromstring|XML)\s*\(|\bminidom\.(parse|parseString)\s*\(|\bxml\.sax\.(parse|make_parser)\b|\betree\.XMLParser\s*\([^)]*(resolve_entities\s*=\s*True|no_network\s*=\s*False)",
        "reminder": "⚠️ Security Warning: Use defusedxml.ElementTree. Python's stdlib XML parsers are vulnerable to XXE (external entity) and billion-laughs attacks by default.",
    },
    {
        "ruleName": "pickle_variants_load",
        "regex": r"\b(cPickle|cloudpickle|dill)\.(load|loads)\s*\(",
        "reminder": _UNSAFE_DESERIALIZATION_REMINDER,
    },
    {
        "ruleName": "outerHTML_xss",
        "substrings": [".outerHTML =", ".outerHTML="],
        "reminder": "⚠️ Security Warning: Use textContent or sanitize with DOMPurify. outerHTML assignment is an XSS sink equivalent to innerHTML.",
    },
    {
        "ruleName": "insertAdjacentHTML_xss",
        "substrings": [".insertAdjacentHTML("],
        "reminder": "⚠️ Security Warning: Use insertAdjacentText() or sanitize with DOMPurify. insertAdjacentHTML is an XSS sink.",
    },
    {
        "ruleName": "script_src_without_sri",
        # Detect remote code execution via dynamic import/eval of fetched content.
        # Negative lookahead after src checks for integrity= anywhere in the remaining tag.
        "regex": (
            r"<script\s+(?![^>]{0,400}integrity\s*=)"
            r"[^>]{0,200}src\s*=\s*[\x22\x27](?:https?:)?//"
            r"[^\x22\x27]{1,300}[\x22\x27]"
            r"[^>]{0,100}>"
        ),
        "reminder": '⚠️ Security Warning: Add integrity="sha384-..." crossorigin="anonymous" to external script tags. Loading scripts without Subresource Integrity exposes you to CDN compromise.',
    },
    {
        "ruleName": "torch_unsafe_load",
        # Suppressed by weights_only=True on the same line (within 200 chars). weights_only=False
        # still triggers. Multi-line calls false-positive — same known limitation as unsafe_yaml_load.
        "regex": r"(?:\btorch\.load|\.torch_load)\s*\((?![^)\n]{0,200}weights_only\s*=\s*True)",
        "reminder": _UNSAFE_TORCH_LOAD_REMINDER,
    },
    {
        "ruleName": "yaml_unsafe_load_variants",
        # yaml.unsafe_load (stdlib alias) plus unsafe wrapper method names seen in the wild.
        # Bare yaml.load() is unsafe_yaml_load's job (RuleId 12).
        "regex": r"(?:\byaml\.unsafe_load|\.yaml_unsafe_load)\s*\(",
        "reminder": _UNSAFE_YAML_LOAD_REMINDER,
    },
    {
        "ruleName": "pickle_wrapper_load",
        # Library APIs that unpickle without saying "pickle". numpy.load only triggers
        # when allow_pickle=True is explicit (defaults to False since numpy 1.16.3).
        "regex": r"\bjoblib\.load\s*\(|\b(?:pd|pandas)\.read_pickle\s*\(|\.cloudpickle_load\s*\(|\b(?:np|numpy)\.load\s*\([^)\n]{0,200}allow_pickle\s*=\s*True",
        "reminder": _UNSAFE_DESERIALIZATION_REMINDER,
    },
    {
        # Two rules and not one, because they are believed to different
        # degrees. `AKIA` followed by sixteen upper-case characters is an AWS
        # key id and nothing else; `token = "…"` is a guess about a name, and
        # is ranked and filtered accordingly.
        #
        # Every branch is written so `scanner._literal_gate` can derive a
        # mandatory substring from it — `(?:ghp_|gho_|ghu_)` rather than
        # `gh[pou]_`, which parses to a character class and gates nothing.
        # Same language, and the rule is then pre-filtered like the rest.
        "ruleName": "hardcoded_credential",
        # Read before `code_only` blanks string literals: a credential lives
        # inside the literal by definition, which is the one place this sweep
        # is built not to look. Same reason `js_catalog.imports` reads raw.
        "raw": True,
        "regex": (
            r"\b(?:AKIA|ASIA|AROA|AIDA|ANPA|AIPA)[0-9A-Z]{16}\b"
            r"|\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[0-9A-Za-z]{36}\b"
            r"|\bgithub_pat_[0-9A-Za-z_]{60,}\b"
            r"|\b(?:xoxb-|xoxa-|xoxp-|xoxr-|xoxs-)[0-9A-Za-z-]{10,}\b"
            r"|\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b"
            r"|\bAIza[0-9A-Za-z_\-]{35}\b"
            # The header alone matches the module that redacts PEM blocks and
            # the test that writes a stub file: measured on hermes/, both.
            # Requiring the body that follows asks whether there is a key
            # here, not whether the words are.
            r"|-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"
            r"(?:[\s\x22\x27]|\\[nrt])*[A-Za-z0-9+/]{16}"
            r"|\beyJ[0-9A-Za-z_\-]{10,}\.eyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}\b"
            r"|\b(?:postgres|postgresql|mysql|mariadb|mongodb|mongodb\+srv"
            r"|redis|rediss|amqp|amqps)://[^\s:@/]+:[^\s:@/]+@"
        ),
        "reminder": """⚠️ Security Warning: This looks like a live credential written into the source.

A key in the repository is a key in every clone, every fork, every CI log and every backup, and rotating it is the only remediation — removing the line is not, because the history keeps it.

Read it from the environment or a secret manager at the point of use, and rotate whatever was committed. If this is a fixture, make it obviously one (the provider's documented example value, or a name containing EXAMPLE/PLACEHOLDER) so it stops being reported.""",
    },
    {
        "ruleName": "hardcoded_secret_assignment",
        "raw": True,
        # Bare `key` is not a secret word. Measured on hermes/: it alone
        # produced 373 findings, and the ones that were not `STORAGE_KEY =
        # 'hermes.desktop.layoutTree.v2'` were `key: 'credits.grant_spent'`
        # and a Japanese translation string. What is claimed here is a name
        # that can only mean a credential.
        #
        # Written out in three casings rather than folded with `(?i:…)`, for
        # two reasons that happen to agree: a reader sees exactly which names
        # are claimed, and every alternative is four characters or more, so
        # `scanner._literal_gate` can derive a pre-filter. Folded, this rule
        # ran on every file in scope and cost 10.6 s of a 17 s sweep.
        #
        # An identifier prefix in front of the name — `[A-Za-z0-9_]*` — is
        # what one writes first and it is quadratic: that spelling took the
        # sweep past two minutes, backtracking against the alternation once
        # per starting position. It is also unnecessary, since `API_KEY` is
        # recognised by the `API_KEY` that ends it.
        "regex": (
            r"(?:secret|Secret|SECRET"
            r"|token|Token|TOKEN"
            r"|password|Password|PASSWORD"
            r"|passwd|Passwd|PASSWD"
            r"|passphrase|Passphrase|PASSPHRASE"
            r"|credential|Credential|CREDENTIAL"
            r"|api_key|API_KEY|apiKey|apikey|APIKEY"
            r"|access_key|ACCESS_KEY|accessKey"
            r"|private_key|PRIVATE_KEY|privateKey"
            r"|signing_key|SIGNING_KEY|signingKey"
            r"|encryption_key|ENCRYPTION_KEY|encryptionKey)s?"
            r"[\x22\x27]?\s*[:=]\s*"
            r"[\x22\x27][^\x22\x27\s\\]{16,80}[\x22\x27]"
        ),
        "reminder": """⚠️ Security Warning: A name that says "secret" is assigned a literal here.

Read the value from the environment (os.environ / process.env) or from a secret manager, and keep the literal out of the repository — a clone, a CI log or a fork keeps it forever, and rotating is then the only remediation.

If this value is not a secret, or is a placeholder, say so in the name or the value (EXAMPLE, PLACEHOLDER, <your-key-here>) and the rule stops reporting it.""",
    },
]


class RuleId(IntEnum):
    """
    Stable numeric IDs for SECURITY_PATTERNS rules, emitted via the PostToolUse
    metrics field so telemetry can attribute pattern-warning events to
    specific checks. The metrics schema only allows bool|number values (no
    strings), so rule names can't be sent directly.

    Values are frozen: do not renumber existing entries. Append new ones.
    """
    GITHUB_ACTIONS_WORKFLOW = 1
    CHILD_PROCESS_EXEC = 2
    NEW_FUNCTION_INJECTION = 3
    EVAL_INJECTION = 4
    REACT_DANGEROUSLY_SET_HTML = 5
    DOCUMENT_WRITE_XSS = 6
    INNERHTML_XSS = 7
    PICKLE_DESERIALIZATION = 8
    OS_SYSTEM_INJECTION = 9
    PYTHON_SUBPROCESS_SHELL = 10
    GO_EXEC_SHELL_INJECTION = 11
    UNSAFE_YAML_LOAD = 12
    NODE_CREATECIPHER_NO_IV = 13
    AES_ECB_MODE = 14
    TLS_VERIFICATION_DISABLED = 15
    MARSHAL_LOADS = 16
    SHELVE_OPEN = 17
    XML_UNSAFE_PARSE = 18
    PICKLE_VARIANTS_LOAD = 19
    OUTERHTML_XSS = 20
    INSERTADJACENTHTML_XSS = 21
    SCRIPT_SRC_WITHOUT_SRI = 22
    TORCH_UNSAFE_LOAD = 23
    YAML_UNSAFE_LOAD_VARIANTS = 24
    PICKLE_WRAPPER_LOAD = 25
    HARDCODED_CREDENTIAL = 26
    HARDCODED_SECRET_ASSIGNMENT = 27


_RULE_NAME_TO_ID = {
    "github_actions_workflow": RuleId.GITHUB_ACTIONS_WORKFLOW,
    "child_process_exec": RuleId.CHILD_PROCESS_EXEC,
    "new_function_injection": RuleId.NEW_FUNCTION_INJECTION,
    "eval_injection": RuleId.EVAL_INJECTION,
    "react_dangerously_set_html": RuleId.REACT_DANGEROUSLY_SET_HTML,
    "document_write_xss": RuleId.DOCUMENT_WRITE_XSS,
    "innerHTML_xss": RuleId.INNERHTML_XSS,
    "pickle_deserialization": RuleId.PICKLE_DESERIALIZATION,
    "os_system_injection": RuleId.OS_SYSTEM_INJECTION,
    "python_subprocess_shell": RuleId.PYTHON_SUBPROCESS_SHELL,
    "go_exec_shell_injection": RuleId.GO_EXEC_SHELL_INJECTION,
    "unsafe_yaml_load": RuleId.UNSAFE_YAML_LOAD,
    "node_createcipher_no_iv": RuleId.NODE_CREATECIPHER_NO_IV,
    "aes_ecb_mode": RuleId.AES_ECB_MODE,
    "tls_verification_disabled": RuleId.TLS_VERIFICATION_DISABLED,
    "marshal_loads": RuleId.MARSHAL_LOADS,
    "shelve_open": RuleId.SHELVE_OPEN,
    "xml_unsafe_parse": RuleId.XML_UNSAFE_PARSE,
    "pickle_variants_load": RuleId.PICKLE_VARIANTS_LOAD,
    "outerHTML_xss": RuleId.OUTERHTML_XSS,
    "insertAdjacentHTML_xss": RuleId.INSERTADJACENTHTML_XSS,
    "script_src_without_sri": RuleId.SCRIPT_SRC_WITHOUT_SRI,
    "torch_unsafe_load": RuleId.TORCH_UNSAFE_LOAD,
    "yaml_unsafe_load_variants": RuleId.YAML_UNSAFE_LOAD_VARIANTS,
    "pickle_wrapper_load": RuleId.PICKLE_WRAPPER_LOAD,
    "hardcoded_credential": RuleId.HARDCODED_CREDENTIAL,
    "hardcoded_secret_assignment": RuleId.HARDCODED_SECRET_ASSIGNMENT,
}

# Fail loudly at import time if a pattern is added without a RuleId.
# This fires in pytest on every PR, so desync is caught before merge.
# The rules an audit may report. A rule with neither a regex nor a substring
# list has only a `path_check`, so it fires because a file exists rather than
# because of anything written in it. That is a write-time reminder — the shape
# `plugins/write-guard` wants, and gets, from `scan_text` — not a statement
# about existing code: on Hermes it produced 28 of 30 findings, every one of
# them saying "this repository has GitHub workflows".
AUDIT_PATTERNS = [
    rule for rule in SECURITY_PATTERNS
    if rule.get("regex") or rule.get("substrings")
]


assert set(_RULE_NAME_TO_ID) == {p["ruleName"] for p in SECURITY_PATTERNS}, (
    f"RuleId enum out of sync with SECURITY_PATTERNS: "
    f"missing={set(p['ruleName'] for p in SECURITY_PATTERNS) - set(_RULE_NAME_TO_ID)}, "
    f"extra={set(_RULE_NAME_TO_ID) - set(p['ruleName'] for p in SECURITY_PATTERNS)}"
)


def rule_names_to_mask(rule_names):
    """Pack a set of rule names into a bitmask. Bit N set means RuleId(N) matched.
    User-defined patterns (rule_name starting with "user:") have no static
    RuleId and are excluded from the mask."""
    mask = 0
    for name in rule_names:
        if name in _RULE_NAME_TO_ID:
            mask |= 1 << _RULE_NAME_TO_ID[name]
    return mask
