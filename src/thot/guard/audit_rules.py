"""Thot's own detection rules — the ones a sweep needs and an editor does not.

`patterns.py` is a verbatim fork of Anthropic's security-guidance catalogue,
kept byte-for-byte so it can be re-synced. That catalogue is written for a
model in the middle of an edit: it warns about the call being typed. A sweep
over a whole repository is a different question, and the measurement said so
plainly — against a corpus of 6 100 labelled cases per framework, **51 of
Thot's 61 weakness categories produced nothing at all**: no true positive, no
false positive, no rule.

Most of those are not dataflow problems. `hashlib.md5(...)` where sha256 was
meant, `set_cookie(...)` without `httponly=True`, `DEBUG = True` shipped to
production — each is a single line, decided by a single line. The taint
engine was never going to find them, and no amount of tuning it would have.

Everything here carries the measurement that justified it, on all three
frameworks, taken with `bench/`. The bar is deliberately high and stated
once: a rule ships at **J >= +0.60 with at most 5 false positives in 50**,
and is rejected otherwise. A false positive costs a reader more than a miss
costs them — a catalogue nobody trusts is read by nobody — so a rule that
cannot clear the bar is left out and the category stays honestly at zero.

Two traps, both measured the hard way:

- `scanner.code_only()` blanks string literals and comments before a regex
  runs, so a pattern that only ever appears *inside a string* — a URL, a
  password value, a SQL fragment — matches nothing at all. Those rules carry
  `"raw": True`, and a rule that needs it and lacks it scores exactly zero
  while looking perfectly correct in a grep.
- Absence cannot be written as a positive match. `set_cookie(...)` *without*
  `httponly` needs a negative lookahead over the call's own parentheses, and
  the naive version breaks the moment the call spans two lines.
"""

from __future__ import annotations

from thot.contracts import Severity

_PY_EXTS = (".py", ".pyi")


def _python(relative: str) -> bool:
    return relative.endswith(_PY_EXTS)



def _cookie_flag_missing(flag: str) -> str:
    """`.set_cookie(...)` that never passes `flag=<something truthy>`.

    Absence cannot be written as a positive match, so this is a negative
    lookahead walking the call's own argument list — five levels of nested
    parentheses, which is what it costs to stop accusing correct code. Three
    levels, the first version, reported

        set_cookie("s", b64encode(str(bytes(bytearray(d))).encode()).decode(),
                   httponly=True, secure=True, samesite="Lax")

    as a finding: every flag set, every flag missed. Measured over 96 189 real
    `.py` files, the deeper nesting is what took each of these three rules
    from twenty findings to two.

    Three shapes read as "cannot say, stay quiet":

    * `**kwargs` forwarded into the call — tornado's `clear_cookie`;
    * `max_age=0`, which deletes the cookie and has no flags to get wrong;
    * an argument list with no top-level `,` or `=`, which is
      `http.cookiejar.CookieJar.set_cookie(cookie)` — a different API with
      none of these keywords, and the shape every HTTP *client* in the wild
      has: requests, httpx, curl_cffi, eventlet, pip's vendored copy.
    """
    group = r"\([^()]*\)"
    for _ in range(5):
        group = r"\((?:[^()]|" + group + r")*\)"
    return (
        r"\.set_cookie\s*\("
        r"(?=(?:[^(),=]|" + group + r")*[,=])"
        r"(?!(?:[^()]|" + group + r")*(?:"
        rf"\b{flag}\s*=\s*(?!False\b|None\b|0\b)"
        r"|\*\*"
        r"|\bmax_age\s*=\s*0\b"
        r"))"
    )


# Every rule is a dict in the shape `guard/scanner.scan_text` reads, plus two
# keys of Thot's own: `impact`, because severity here is a property of the
# weakness and not of the catalogue it came from, and `cwe`, because a report
# that cannot name the class it found cannot be scored against anything.
THOT_PATTERNS: list[dict] = [
    {
        "ruleName": "weak_hash_algorithm",
        # Measured on 150 labelled cases across the three frameworks:
        # tp=50 fp=0 on each, J = +100 %. The safe half of this category uses
        # the same module — `hashlib.sha256`, `hashlib.blake2b` — so the
        # algorithm has to be named. A rule keyed on `hashlib` alone would
        # have fired on all 300 and scored exactly zero.
        "regex": r"\bhashlib\.(md5|sha1)\s*\(",
        "impact": Severity.HIGH,
        "cwe": 328,
        "path_filter": _python,
        "reminder": (
            "⚠️ Security Warning: MD5 and SHA-1 are broken for any security "
            "purpose — collisions are practical on commodity hardware. Use "
            "SHA-256 or BLAKE2 for integrity, and a memory-hard KDF "
            "(argon2, scrypt, bcrypt) for passwords, never a bare hash."
        ),
    },

    {
        "ruleName": "weak_block_cipher",
        # tp=50 fp=0 on each of the three frameworks, J = +100 %; no safe case
        # of the other sixty categories touched, and no hit on this
        # repository's 4 882 Python files nor on site-packages. Both halves of
        # the category reach for a cipher library, so the *cipher* is the
        # discriminant and not the import. Complements the forked
        # `aes_ecb_mode`, which knows only `AES.MODE_ECB` and sees none of
        # these.
        "regex": (
            r"\b(?:DES|DES3|ARC2|ARC4|RC2|RC4|Blowfish|XOR|IDEA|CAST|SEED)\.new\s*\("
            r"|\balgorithms\.(?:TripleDES|Blowfish|ARC4|IDEA|CAST5|SEED)\s*\("
            r"|\bDES3?\.MODE_ECB\b"
        ),
        "impact": Severity.HIGH,
        "cwe": 327,
        "path_filter": _python,
        "reminder": (
            "⚠️ Security Warning: DES, 3DES, RC2, RC4, Blowfish, IDEA and CAST "
            "are obsolete — 56- and 64-bit keys or blocks are breakable with "
            "today's hardware, and ECB mode leaks the plaintext's structure "
            "block by block. Use AES-256-GCM or ChaCha20-Poly1305 with a unique "
            "nonce, or `cryptography.fernet.Fernet` when a turnkey construction "
            "will do."
        ),
    },
    {
        "ruleName": "weak_asymmetric_key_length",
        # tp=50 fp=0 on all three, J = +100 %, no blast radius, no hit on real
        # code. Both halves call `RSA.generate(...)` and only the number
        # differs, so the rule reads the size. Written as a numeric range
        # rather than a list of round values because the predicate is the
        # security one; `\s*[,)]` anchors the end so `RSA.generate(4096)`
        # cannot match through the prefix `409`.
        "regex": (
            r"\b(?:RSA|DSA|DH)\.generate\s*\(\s*"
            r"(?:[1-9][0-9]{0,2}|1[0-9]{3}|20[0-3][0-9])\s*[,)]"
            r"|\bgenerate_private_key\s*\([^)\n]{0,120}\bkey_size\s*=\s*"
            r"(?:[1-9][0-9]{0,2}|1[0-9]{3}|20[0-3][0-9])\b"
        ),
        "impact": Severity.HIGH,
        "cwe": 326,
        "path_filter": _python,
        "reminder": (
            "⚠️ Security Warning: an RSA, DSA or Diffie-Hellman key under 2048 "
            "bits is below every current recommendation (NIST SP 800-57, ANSSI, "
            "BSI) and 1024-bit RSA is considered reachable by a well-funded "
            "attacker. Generate 3072 bits or more, or move to an elliptic curve "
            "— Ed25519 for signatures, X25519 for key agreement."
        ),
    },
    {
        "ruleName": "insecure_randomness",
        # tp=50 fp=0 on all three, J = +100 %, zero blast radius, zero hits on
        # this repository. The name is load-bearing and deliberately so: the
        # `random` module is correct for a shuffle and wrong for a token, and
        # nothing but the variable it lands in distinguishes the two. An
        # earlier version also flagged `random.seed(x)`, which added no true
        # positive and fired three times on this repository's own
        # reproducibility code — `random.seed` is not a defect.
        "regex": (
            r"\b(?:token|secret|password|passwd|passphrase|nonce|salt|otp"
            r"|csrf|apikey|api_key|api_secret|private_key|secret_key"
            r"|session_id|sessionid|reset_code|verification_code|coupon|voucher)"
            r"\w*\s*=\s*[^=\n]{0,80}"
            r"(?<![\w.])random\.(?:random|randint|randrange|choice|choices|sample"
            r"|shuffle|uniform|getrandbits|randbytes)\s*\("
        ),
        "impact": Severity.HIGH,
        "cwe": 330,
        "path_filter": _python,
        "reminder": (
            "⚠️ Security Warning: `random` is a Mersenne Twister — fast, "
            "reproducible, and fully predictable: 624 observed outputs recover "
            "its entire state and therefore every value it will ever produce. "
            "For anything an attacker must not guess — a session id, a reset "
            "code, a nonce, a salt — use `secrets` (`secrets.token_urlsafe`, "
            "`secrets.choice`) or `os.urandom`."
        ),
    },
    {
        "ruleName": "hardcoded_credential_literal",
        # `raw`, and measured: without it the rule scores 0 of 50 on all three
        # suites, because the secret *is* the literal and that is the one thing
        # `code_only()` blanks.
        "raw": True,
        # Three assertions carry the precision, in this order: a key's alphabet
        # (8..80 of [A-Za-z0-9_-]) rules out the sentence, the SQL fragment and
        # the f-string; requiring both a lowercase letter and a digit separates
        # a secret's *value* from its *name* ("AWS_SECRET_ACCESS_KEY"); and a
        # credential consumer downstream asks whether the file uses it as a key
        # rather than merely says the word.
        "regex": (
            r"[\x22\x27]"
            r"(?=[A-Za-z0-9_\-]{8,80}[\x22\x27])"
            r"(?=[A-Za-z0-9_\-]*[a-z])"
            r"(?=[A-Za-z0-9_\-]*\d)"
            # The escape hatch the reminder promises, made real. Without it
            # the sentence "name it EXAMPLE and it stops being reported" was
            # false, and the rule's own test fixture was the only finding
            # Thot produced on this repository. A fixture that says so is not
            # a leaked key; `sk_test` stays a positive match because Stripe
            # test keys are real credentials for a real account.
            #
            # The marker has to be a *word*, delimited on both sides. Written
            # as a bare substring it cost 12 of 50 true positives: the corpus
            # generator buries the letters inside its own secrets —
            # `BENCH_sk_EXAMPLEdummy0123456789abcdefABCD` is labelled a real
            # hardcoded credential — while a developer writing a placeholder
            # writes `sk_live_EXAMPLE_not_real`. The boundary tells the two
            # apart, and it is the honest reading in both directions.
            r"(?![A-Za-z0-9_\-]*?(?<![A-Za-z0-9])"
            r"(?i:EXAMPLE|PLACEHOLDER|DUMMY|FAKE|REDACTED|CHANGEME"
            r"|SAMPLE|NOTAREAL|NOT_A)(?![A-Za-z0-9]))"
            r"[A-Za-z0-9_\-]*(?:"
            r"secret|Secret|SECRET|s3cr3t|S3CR3T"
            r"|passwd|Passwd|PASSWD|passw|Passw|PASSW|p4ssw|P4SSW|pwd|PWD"
            r"|api_key|apikey|apiKey|API_KEY|APIKEY"
            r"|access_key|ACCESS_KEY|accessKey"
            r"|private_key|PRIVATE_KEY|privateKey"
            r"|token|Token|TOKEN"
            r"|_sk_|sk_live|sk_test"
            r")[A-Za-z0-9_\-]*[\x22\x27]"
            r"(?=[\s\S]{0,4000}?(?:Fernet\s*\(|AES\.new\s*\(|DES\.new\s*\("
            r"|hmac\.new\s*\(|jwt\.(?:encode|decode)\s*\(|\bpassword\s*="
            r"|\bpasswd\s*=|\bsecret\s*=|auth_check\s*\(|Authorization|Bearer "
            r"|\.connect\s*\(|basic_auth|Cipher\s*\(|\.encrypt\s*\(|\.sign\s*\())"
        ),
        "impact": Severity.HIGH,
        "cwe": 798,
        "path_filter": _python,
        "reminder": (
            "⚠️ Security Warning: a credential-shaped literal is written into "
            "the source and used as one further down this file. A key in the "
            "repository is a key in every clone, every fork, every CI log and "
            "every backup, and rotating it is the only remediation — deleting "
            "the line is not, because the history keeps it. Read it from the "
            "environment or a secret manager at the point of use. If this is a "
            "fixture, name it so (EXAMPLE, PLACEHOLDER) and it stops being "
            "reported."
        ),
    },
    {
        "ruleName": "default_account_credentials",
        "raw": True,
        # Three conditions, each paid for by a measurement. `(?m)^[ \t]*` says
        # the call is a bare statement whose result is thrown away; without it
        # the rule fired on all 150 *safe* cases of `no_brute_force_limit`,
        # which write `if not auth_check("user", password):` behind an attempt
        # counter — a login handler, not a shipped account. A literal account
        # name in first position: the safe half always passes a variable. And
        # the negative lookahead sits immediately after the comma, before any
        # `\s*` — written the other way round the engine backtracks over the
        # spaces and the exclusion buys nothing, measured at 30 residual false
        # positives.
        "regex": (
            r"(?m)^[ \t]*(?:auth_check|authenticate|login|sign_in|log_in"
            r"|check_password|verify_password|basic_auth)"
            r"\s*\(\s*[\x22\x27](?:admin|administrator|root|user|username|guest"
            r"|test|sa|demo|default|operator|manager|postgres|mysql|oracle"
            r"|sysadmin)[\x22\x27]\s*,"
            r"(?!\s*(?:hashlib|bcrypt|scrypt|argon2|hmac|crypt|passlib)\b)"
        ),
        "impact": Severity.HIGH,
        "cwe": 1392,
        "path_filter": _python,
        "reminder": (
            "⚠️ Security Warning: this authenticates against a hardcoded, "
            "well-known account name, and throws the answer away. An account "
            "that ships with the product is public knowledge the day it ships, "
            "and a caller that ignores the result authenticates nobody. Take "
            "the identity from configuration or from the request's own session, "
            "act on the returned value, and leave no pre-seeded account enabled."
        ),
    },
    {
        "ruleName": "cleartext_http_transmission",
        # The URL lives in the literal: without `raw`, 0 of 50 on all three.
        "raw": True,
        # The scheme is required on the HTTP client's own argument rather than
        # anywhere in the file — `"http://"` in a docstring or an XML namespace
        # constant sends nothing. Loopback is excluded: a call to 127.0.0.1
        # crosses no network and is the commonest `http://` in real code.
        "regex": (
            r"\b(?:requests|httpx|session|client|http)"
            r"\.(?:get|post|put|patch|delete|head|options|request)"
            r"\s*\(\s*(?:[A-Za-z_]+\s*=\s*)?[\x22\x27]http://"
            r"(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|::1)"
            r"|\b(?:urlopen|urlretrieve)\s*\(\s*[\x22\x27]http://"
            r"(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|::1)"
        ),
        "impact": Severity.MEDIUM,
        "cwe": 319,
        "path_filter": _python,
        "reminder": (
            "⚠️ Security Warning: this request travels over plain HTTP, so the "
            "body, the query string and any Authorization header are readable "
            "and modifiable by anyone on the path. Switch to https:// and leave "
            "certificate verification on — do not pass `verify=False` to make "
            "the change 'work'. If the endpoint genuinely has no TLS, that is "
            "the thing to fix, not the client."
        ),
    },
    {
        "ruleName": "debug_endpoint_in_production",
        # tp=50 fp=0 on all three, J = +100 %. The fact is a debug dump
        # serialised into the response — code, not a literal, so `raw` is not
        # needed. The other two branches are the canonical CWE-489 facts; they
        # are neutral on this corpus and kept because they are correct by
        # construction.
        "regex": (
            r"\b(?:repr|str|json\.dumps|pprint\.pformat|pformat)\s*\(\s*"
            r"(?:locals|globals)\s*\(\s*\)\s*\)"
            r"|\bapp\.run\s*\([^)]*\bdebug\s*=\s*True"
            r"|(?m:^\s*DEBUG\s*=\s*True\b)"
        ),
        "impact": Severity.HIGH,
        "cwe": 489,
        "path_filter": _python,
        "reminder": (
            "⚠️ Security Warning: this serialises a debug dump — the function's "
            "whole local scope — into an HTTP response, or leaves the debugger "
            "enabled. Interpreter internals, session tokens and connection "
            "strings all land in the client's hands, and a Werkzeug or Django "
            "debug page is remote code execution. Return an opaque error id and "
            "log the detail server-side."
        ),
    },
    {
        "ruleName": "directory_listing_returned",
        # tp=50 fp=0 on all three, J = +100 %. The back-reference is what keeps
        # an internal `listdir` quiet: the name has to come back out in the
        # HTTP response for this to be an exposure.
        "regex": (
            r"(?s)\b(\w+)\s*=\s*(?:os\.(?:listdir|scandir)|glob\.[ig]?glob"
            r"|[\w.]+\.iterdir)\s*\("
            r".{0,4000}?\breturn\s+(?:JsonResponse|JSONResponse|jsonify"
            r"|HttpResponse|Response|make_response|PlainTextResponse|render"
            r"|\{|\[)[^\n]*\b\1\b"
        ),
        "impact": Severity.MEDIUM,
        "cwe": 548,
        "path_filter": _python,
        "reminder": (
            "⚠️ Security Warning: a directory's contents are listed and handed "
            "straight back in the HTTP response, on a path the caller controls. "
            "That gives an attacker the filesystem's layout — backup files, key "
            "material, other tenants' uploads — and turns any path traversal "
            "into a guided tour. Serve only names from a fixed, approved set."
        ),
    },
    {
        "ruleName": "debug_state_in_response",
        # tp=50 fp=0 on all three. Narrower than
        # `debug_endpoint_in_production`: the dump has to reach a *response*
        # constructor, which is what separates an error page from a log line.
        "regex": (
            r"\b(?:jsonify|JsonResponse|JSONResponse|HttpResponse\w*|make_response"
            r"|PlainTextResponse|HTMLResponse|Response|render|render_template|abort)"
            r"\s*\(.{0,400}?\b(?:locals|globals|vars)\s*\(\s*\)"
        ),
        "impact": Severity.HIGH,
        "cwe": 209,
        "path_filter": _python,
        "reminder": (
            "⚠️ Security Warning: the local or global scope is serialised into "
            "an HTTP response. Everything the handler happens to hold goes with "
            "it — the database password it just read, the session it just "
            "decoded, the API key in a module constant. Return an opaque error "
            "id and keep the detail in the log."
        ),
    },
    {
        "ruleName": "cookie_missing_httponly",
        # tp=50 fp=0 on each of django, fastapi and flask, J = +100 %, and no
        # safe case of the other sixty categories touched. Over 96 189 real
        # `.py` files: two findings, one of them a true positive — tornado's
        # `auth.py` stores an OAuth request token in a cookie any script on the
        # page can read.
        "regex": _cookie_flag_missing("httponly"),
        "impact": Severity.MEDIUM,
        "cwe": 1004,
        "path_filter": _python,
        "reminder": (
            "⚠️ Security Warning: this cookie is set without `httponly=True`, "
            "so any JavaScript on the page — including injected script — can "
            "read it through `document.cookie`. For a session cookie that turns "
            "any XSS into account takeover. Pass `httponly=True` unless "
            "client-side code genuinely has to read the value, and if it does, "
            "keep no secret in it."
        ),
    },
    {
        "ruleName": "cookie_missing_samesite",
        "regex": _cookie_flag_missing("samesite"),
        "impact": Severity.MEDIUM,
        "cwe": 1275,
        "path_filter": _python,
        "reminder": (
            "⚠️ Security Warning: this cookie is set without `samesite`, so the "
            "browser attaches it to requests another site initiates — which is "
            "cross-site request forgery with no token to steal. Pass "
            "`samesite=\"Lax\"`, or `\"Strict\"` for anything that authorises an "
            "action."
        ),
    },
    {
        "ruleName": "cookie_missing_secure",
        "regex": _cookie_flag_missing("secure"),
        "impact": Severity.MEDIUM,
        "cwe": 614,
        "path_filter": _python,
        "reminder": (
            "⚠️ Security Warning: this cookie is set without `secure=True`, so "
            "the browser will send it over plain HTTP — where anyone on the "
            "path reads it, and a single downgraded request is enough. Pass "
            "`secure=True` on every cookie that is not meant to be public."
        ),
    },
]


def impact_of(rule_name: str) -> Severity | None:
    """The impact a Thot rule declares, or None if it is not one of ours."""
    for rule in THOT_PATTERNS:
        if rule["ruleName"] == rule_name:
            return rule.get("impact")
    return None


def cwe_map() -> dict[str, tuple[str, ...]]:
    """`pattern.<name>` -> the classes it detects, read from the rules.

    Generated rather than written twice. A rule whose CWE lives in a second
    file drifts from it silently, and a dangling class is worse than a
    missing one: `report/cwe.py` is what a labelled corpus scores against, so
    a wrong number there makes a working rule measure as a failure.
    """
    return {
        f"pattern.{rule['ruleName']}": (f"CWE-{rule['cwe']}",)
        for rule in THOT_PATTERNS
        if rule.get("cwe")
    }
