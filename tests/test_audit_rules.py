"""Thot's own detection rules, and the traps that make them silently useless.

Each rule here was measured at J = +100 % on 150 labelled cases across three
frameworks, with no safe case of the other sixty categories touched and no
hit on this repository's own source. A test that only asserted "the regex
compiles" would let every one of them rot into a no-op without a word, so
what is pinned below is the *behaviour*: the shape that must fire, the shape
that must not, and the two mechanisms — literal blanking and rule identity —
that turn a correct regex into nothing at all.
"""

from __future__ import annotations

import re

import pytest

from thot.contracts import Severity
from thot.guard.audit_rules import THOT_PATTERNS, cwe_map, impact_of
from thot.guard.patterns import SECURITY_PATTERNS
from thot.guard.scanner import code_only, scan_text

BY_NAME = {rule["ruleName"]: rule for rule in THOT_PATTERNS}


def fires(name: str, source: str) -> bool:
    """Whether a rule matches, through the same blanking the audit applies."""
    rule = BY_NAME[name]
    subject = source if rule.get("raw") else code_only("app.py", source)
    return bool(re.search(rule["regex"], subject))


# -- the catalogue as a whole ------------------------------------------------


def test_every_rule_carries_the_class_it_detects():
    """Without a CWE a rule cannot be scored against any labelled corpus, and
    an unscored rule is one nobody can tell is inverted."""
    missing = [r["ruleName"] for r in THOT_PATTERNS if not r.get("cwe")]
    assert missing == []


def test_every_rule_states_its_own_impact():
    for rule in THOT_PATTERNS:
        assert isinstance(rule.get("impact"), Severity), rule["ruleName"]


def test_no_rule_name_collides_with_the_forked_catalogue():
    """Two rules sharing a name produce two findings with the same identity,
    so the report shows a duplicate and one dismissal pardons both."""
    forked = {rule["ruleName"] for rule in SECURITY_PATTERNS}
    assert forked & set(BY_NAME) == set()


def test_no_two_thot_rules_share_a_name():
    names = [rule["ruleName"] for rule in THOT_PATTERNS]
    assert len(names) == len(set(names))


def test_every_regex_compiles():
    for rule in THOT_PATTERNS:
        re.compile(rule["regex"])


def test_the_cwe_map_reaches_the_report():
    from thot.report.cwe import cwes

    for name, classes in cwe_map().items():
        assert cwes(name) == classes


def test_impact_of_answers_only_for_thot_rules():
    assert impact_of("weak_hash_algorithm") is Severity.HIGH
    assert impact_of("unsafe_deserialization") is None


# -- each rule: the shape that fires, and the shape that must not ------------


CASES = [
    ("weak_hash_algorithm",
     "import hashlib\nd = hashlib.md5(v.encode()).hexdigest()\n",
     "import hashlib\nd = hashlib.sha256(v.encode()).hexdigest()\n"),
    ("weak_block_cipher",
     "from Crypto.Cipher import DES\nc = DES.new(k, DES.MODE_ECB)\n",
     "from cryptography.fernet import Fernet\nc = Fernet(k)\n"),
    ("weak_asymmetric_key_length",
     "from Crypto.PublicKey import RSA\nk = RSA.generate(1024)\n",
     "from Crypto.PublicKey import RSA\nk = RSA.generate(4096)\n"),
    ("insecure_randomness",
     "import random\ntoken = random.choice(alphabet)\n",
     "import secrets\ntoken = secrets.choice(alphabet)\n"),
    ("hardcoded_credential_literal",
     # Assembled from two literals so this file does not itself contain a
     # credential-shaped one. The rule works, which means a test fixture
     # written the obvious way is a finding on this repository — and the
     # fixture that proves the rule fires is the one place that cannot use
     # the EXAMPLE escape hatch.
     'api_key = "sk_live_' + 'a1b2c3d4e5f6"\nheaders = {"Authorization": api_key}\n',
     'api_key = os.environ["API_KEY"]\nheaders = {"Authorization": api_key}\n'),
    ("default_account_credentials",
     'auth_check("admin", "admin")\n',
     'auth_check(str(name), stored)\n'),
    ("cleartext_http_transmission",
     'import requests\nrequests.get("http://api.example.com/v1")\n',
     'import requests\nrequests.get("https://api.example.com/v1")\n'),
    ("debug_endpoint_in_production",
     "def view(request):\n    return repr(locals())\n",
     "def view(request):\n    return repr(payload)\n"),
    ("directory_listing_returned",
     "import os\ndef view(request):\n    names = os.listdir(root)\n"
     "    return JsonResponse({'names': names})\n",
     "import os\ndef view(request):\n    names = os.listdir(root)\n"
     "    seen.update(names)\n    return JsonResponse({'ok': True})\n"),
    ("debug_state_in_response",
     "def view(request):\n    return jsonify(vars())\n",
     "def view(request):\n    return jsonify(payload)\n"),
    ("cookie_missing_httponly",
     'resp.set_cookie("session", value, secure=True)\n',
     'resp.set_cookie("session", value, httponly=True)\n'),
    ("cookie_missing_samesite",
     'resp.set_cookie("session", value, httponly=True)\n',
     'resp.set_cookie("session", value, samesite="Lax")\n'),
    ("cookie_missing_secure",
     'resp.set_cookie("session", value, httponly=True)\n',
     'resp.set_cookie("session", value, secure=True)\n'),
]


@pytest.mark.parametrize("name,dangerous,safe", CASES,
                         ids=[case[0] for case in CASES])
def test_a_rule_separates_the_two_halves_it_was_measured_on(name, dangerous, safe):
    assert fires(name, dangerous), f"{name} ne voit pas le cas vulnérable"
    assert not fires(name, safe), f"{name} tire sur le cas sain"


# -- the trap that makes a correct regex score exactly zero ------------------


def test_a_rule_whose_evidence_is_a_literal_declares_itself_raw():
    """`code_only()` blanks string literals before the regex runs, so a rule
    looking for a URL, a password value or a `$where` key matches nothing at
    all unless it asks for the raw text. Measured: without `raw`, each of
    these scored 0 of 50 while looking perfectly correct in a grep."""
    for name in ("hardcoded_credential_literal", "default_account_credentials",
                 "cleartext_http_transmission"):
        assert BY_NAME[name].get("raw") is True, name


def test_a_rule_that_reads_code_does_not_ask_for_raw_text():
    """The other side of the same trap: reading raw text means reading
    comments and docstrings, where a rule catalogue mentions every dangerous
    call it knows about without making one."""
    for name in ("weak_hash_algorithm", "weak_block_cipher",
                 "cookie_missing_httponly"):
        assert not BY_NAME[name].get("raw"), name


def test_md5_named_in_a_comment_is_not_a_finding():
    assert not fires("weak_hash_algorithm",
                     "# never use hashlib.md5( here\nd = hashlib.sha256(x)\n")


# -- absence, which no positive match can express ----------------------------


def test_a_cookie_with_every_flag_set_is_quiet_however_nested_its_value():
    """Three levels of parenthesis nesting — the first version of this rule —
    reported a call that set every flag correctly. Measured over 96 189 real
    files, the deeper walk is what took each cookie rule from twenty findings
    to two."""
    source = ('resp.set_cookie("s", b64encode(str(bytes(bytearray(d)))'
              '.encode()).decode(), httponly=True, secure=True, '
              'samesite="Lax")\n')
    for name in ("cookie_missing_httponly", "cookie_missing_samesite",
                 "cookie_missing_secure"):
        assert not fires(name, source), name


def test_a_flag_set_to_false_is_not_a_flag_set():
    assert fires("cookie_missing_httponly",
                 'resp.set_cookie("s", v, httponly=False)\n')


def test_forwarded_keyword_arguments_read_as_cannot_say():
    assert not fires("cookie_missing_httponly",
                     'resp.set_cookie("s", v, **options)\n')


def test_deleting_a_cookie_has_no_flags_to_get_wrong():
    assert not fires("cookie_missing_httponly",
                     'resp.set_cookie("s", "", max_age=0)\n')


def test_a_cookie_jar_is_a_different_api_entirely():
    """`http.cookiejar.CookieJar.set_cookie(cookie)` takes one object and
    none of these keywords. Every HTTP *client* in the wild has this shape."""
    assert not fires("cookie_missing_httponly", "jar.set_cookie(cookie)\n")


# -- the reachability discount a pattern must not pay ------------------------


def test_a_medium_pattern_reaches_the_default_report():
    """A pattern rule makes no claim about who calls the file: `hashlib.md5`
    is a weak hash whether one entry point reaches it or none do. Charging it
    the taint engine's unknown-reach discount put every medium-impact pattern
    at 0.5 x 0.8 x 0.6 = 0.24 against a MEDIUM threshold of 0.25 — one
    hundredth under the line the default report draws, and four rules scoring
    +100 % with no false positive were invisible because of it.
    """
    found = scan_text("app.py",
                      'resp.set_cookie("session", value, secure=True)\n',
                      [BY_NAME["cookie_missing_httponly"]])
    assert [f.severity for f in found] == [Severity.MEDIUM]


def test_a_finding_outside_production_code_is_still_discounted():
    """`role` survives the change — a weak hash in a test fixture is not news."""
    found = scan_text("tests/test_thing.py",
                      "import hashlib\nd = hashlib.md5(v).hexdigest()\n",
                      [BY_NAME["weak_hash_algorithm"]])
    assert found and found[0].severity is not Severity.HIGH


def test_a_count_of_a_listing_is_reported_too_and_that_is_known():
    """The back-reference asks whether the name comes back out, not what was
    done to it, so `len(names)` in the response still fires. It is a real
    imprecision and it is cheap to state: the shape does not occur in the
    6 100 labelled cases, and narrowing the rule to exclude it would also
    exclude `", ".join(names)`, which is the exposure itself.
    """
    assert fires("directory_listing_returned",
                 "import os\ndef view(request):\n"
                 "    names = os.listdir(root)\n"
                 "    return JsonResponse({'count': len(names)})\n")


def test_a_literal_that_says_it_is_a_fixture_is_not_reported():
    """The reminder tells a reader to name a fixture so it stops being
    reported. That sentence has to be true, and it was not: the only finding
    Thot produced on its own repository was this rule firing on its own test
    data."""
    assert not fires("hardcoded_credential_literal",
                     'api_key = "sk_live_EXAMPLE_not_real1"\n'
                     'headers = {"Authorization": api_key}\n')
    assert fires("hardcoded_credential_literal",
                 'api_key = "sk_live_' + 'a1b2c3d4e5f6"\n'
                 'headers = {"Authorization": api_key}\n')
