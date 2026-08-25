"""Thot's map over HTTP, because Prime cannot consume it any other way.

Prime's MCP client is streamable HTTP and nothing else. `mcp-manager.js:38`
drops every configured server whose `type` is not `"http"` — the comment
there says "stdio servers self-manage in Python", and no such Python exists:
there is not one occurrence of `stdio_client` or `StdioServerParameters` in
the whole of `prime/`. So the `type: stdio` entry `thot fusion wire` wrote
into Prime's `settings.json` was read by nobody. Measured against the
compiled `dist/` that actually runs: `/mcp` never listed Thot and
`mcp.config("thot")` came back `{}`. Half of the fusion was a file.

The transport here is deliberately the smallest thing that is correct: one
POST endpoint, JSON in, JSON out, loopback only, behind a bearer token. No
new dependency — `mcp_server` already speaks JSON-RPC by hand and this only
has to carry it — and no session state, which the specification makes
optional and which nothing on Prime's side asks for.

What it is not is a way onto the network. The endpoint hands out a complete
map of somebody's source tree, so it binds `127.0.0.1`, it refuses a request
without the token, and it refuses a browser Origin: a page the user visits
must not be able to read their repository through their own loopback.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from thot import paths

ENDPOINT = "/mcp"
LOOPBACK = "127.0.0.1"
DEFAULT_PORT = 8787

# Enough entropy that guessing is not a strategy, short enough to paste.
TOKEN_BYTES = 32

# A tool call is a few hundred bytes. The cap exists so a stray client cannot
# make the server hold an arbitrary amount of memory before it has even
# decided the request is authorised.
MAX_BODY = 4 * 1024 * 1024

# Hosts a local agent legitimately sends as its Origin. Anything else is a
# browser that found the port, which is the DNS-rebinding case the MCP
# specification warns about for exactly this kind of server.
#
# Matched as a whole host, never as a prefix of the URL. `startswith` let
# `http://127.0.0.1.evil.example` through — a name anybody can point wherever
# they like, and precisely the attack this check exists to stop.
_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def token_file() -> Path:
    return paths.home() / "mcp-token"


def read_or_make_token() -> str:
    """The shared secret, created once and kept.

    Stable across restarts on purpose: `thot fusion wire` writes it into
    Prime's configuration, and a token that changed on every start would
    turn every reboot into a silent disconnection.

    Created with the mode it needs rather than created and then corrected.
    The two-step version leaves the secret world-readable for as long as it
    takes to reach the `chmod`, which is a window nobody can bound.
    """
    path = token_file()
    try:
        existing = path.read_text(encoding="utf-8").strip()
    except OSError:
        existing = ""
    if existing:
        return existing

    paths.ensure_home()
    token = secrets.token_urlsafe(TOKEN_BYTES)
    try:
        # O_EXCL, so two servers starting at once cannot each mint one and
        # leave the loser's written into Prime's `auth.json`: that would be a
        # disconnection with nothing to explain it.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return _wait_for_token(path)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(token + "\n")
    return token


def _wait_for_token(path: Path, attempts: int = 20) -> str:
    """Read what the process that won the race is in the middle of writing."""
    for _ in range(attempts):
        try:
            held = path.read_text(encoding="utf-8").strip()
        except OSError:
            held = ""
        if held:
            return held
        time.sleep(0.01)
    raise OSError(f"jeton illisible : {path}")


def _origin_is_local(origin: str) -> bool:
    if not origin or origin == "null":
        return True  # a non-browser client sends none
    try:
        host = (urlsplit(origin).hostname or "").lower()
    except ValueError:
        return False
    return host in _LOCAL_HOSTS


class _Quiet(ThreadingHTTPServer):
    """A client that hangs up is not an incident.

    `socketserver.handle_error` prints a full traceback for every exception
    reaching it, and `ConnectionResetError` reaches it whenever a keep-alive
    connection is dropped — which an agent does continuously, by design.
    Twenty lines of stack on stderr for a normal disconnection is how a
    healthy server comes to look broken to whoever reads its log.

    Anything else is still reported, with its traceback: those are bugs, and
    a server that swallowed them would be worse than a noisy one.
    """

    daemon_threads = True
    # A port left in TIME_WAIT must not stop the next start: the wiring in
    # Prime's settings names one port, and it has to be usable again.
    allow_reuse_address = True

    def handle_error(self, request, client_address) -> None:
        import sys
        import traceback

        raised = sys.exc_info()[1]
        if isinstance(raised, (ConnectionResetError, BrokenPipeError, TimeoutError)):
            return
        print(f"[thot-mcp] erreur sur {client_address[0]} : {raised!r}",
              file=sys.stderr, flush=True)
        traceback.print_exc()


def _handler_class(server, token: str, lock: threading.Lock):
    """A request handler bound to one map, one secret, and one lock.

    The lock is not decoration. `Server._tool_context` builds the map on the
    first question about a project, and two agents asking at the same moment
    would otherwise each pay for a full sweep of the tree — two minutes each
    on a repository the size of Hermes — and then race to store the result.
    """

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "thot-mcp"

        # Diagnostics belong on stderr, and one line per tool call is noise:
        # the process is started by another program and its stdout is not a
        # place anyone is reading.
        def log_message(self, format, *args):  # noqa: A002 - stdlib signature
            return

        # -- plumbing ----------------------------------------------------

        def _send(self, status: int, body: bytes = b"",
                  content_type: str = "application/json", *,
                  close: bool = False) -> None:
            self.send_response(status)
            if close:
                # `send_header` sets `close_connection` itself when it sees
                # this value, so the header and the socket agree.
                self.send_header("Connection", "close")
            if body:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _refuse(self, status: int, message: str) -> None:
            """Say no, and hang up.

            Every refusal happens *before* the body is read — that is the
            point of refusing on the token or on `Content-Length` rather
            than after. But `protocol_version = "HTTP/1.1"` keeps the
            connection open, and the unread body is still in the socket:
            the next `handle_one_request` would parse the payload as a
            request line. A client that reuses its connection — which
            Prime's does — sees one 401 turn into a stream of nonsense.
            Draining instead is not an option: 413 exists precisely so a
            large body never has to be read.
            """
            self._send(status, json.dumps({"error": message}).encode("utf-8"),
                       close=True)

        def _authorised(self) -> bool:
            offered = self.headers.get("Authorization", "")
            prefix = "Bearer "
            if not offered.startswith(prefix):
                return False
            # Constant time: the comparison is against a secret, and an
            # attacker who can time it can find it one byte at a time.
            return secrets.compare_digest(offered[len(prefix):].strip(), token)

        # -- methods -----------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802 - stdlib signature
            # The specification lets a server decline the server-to-client
            # stream. Thot never speaks first: every answer it has is the
            # answer to a question.
            self._refuse(405, "Ce serveur ne pousse rien : POST seulement.")

        def do_DELETE(self) -> None:  # noqa: N802 - stdlib signature
            self._refuse(405, "Aucune session à fermer : ce serveur n'en tient pas.")

        def do_POST(self) -> None:  # noqa: N802 - stdlib signature
            if self.path.split("?", 1)[0] != ENDPOINT:
                self._refuse(404, f"Rien ici. Le point d'entrée est {ENDPOINT}.")
                return
            if not _origin_is_local(self.headers.get("Origin", "")):
                self._refuse(403, "Origine refusée : ce serveur est local.")
                return
            if not self._authorised():
                self._refuse(401, "Jeton absent ou faux.")
                return

            if self.headers.get("Transfer-Encoding", "").strip():
                # Read as a zero-length body, a chunked request came back as
                # "JSON illisible" — sending whoever sent it to look for the
                # mistake in the one place it was not.
                self._refuse(411, "Corps en morceaux : indique un Content-Length.")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._refuse(400, "Content-Length illisible.")
                return
            if length > MAX_BODY:
                # Refused on the header, before a byte of it is read.
                self._refuse(413, "Requête trop grande.")
                return

            raw = self.rfile.read(length) if length > 0 else b""
            try:
                payload = json.loads(raw or b"null")
            except ValueError:
                self._send(200, json.dumps({
                    "jsonrpc": "2.0", "id": None,
                    "error": {"code": -32700, "message": "JSON illisible"},
                }).encode("utf-8"))
                return

            requests = payload if isinstance(payload, list) else [payload]
            answers = []
            for request in requests:
                if not isinstance(request, dict):
                    continue
                with lock:
                    try:
                        answer = server.handle(request)
                    except Exception as exc:  # never take the server down
                        answer = {
                            "jsonrpc": "2.0", "id": request.get("id"),
                            "error": {"code": -32603, "message": str(exc)},
                        }
                if answer is not None:
                    answers.append(answer)

            if not answers:
                # Every message was a notification. Nothing to say, and
                # saying nothing is the protocol's own answer for that.
                self._send(202)
                return

            body = answers if isinstance(payload, list) else answers[0]
            self._send(200, json.dumps(body).encode("utf-8"))

    return Handler


def build(root: Path, *, host: str = LOOPBACK, port: int = DEFAULT_PORT,
          token: str | None = None) -> tuple[ThreadingHTTPServer, str]:
    """A bound, not-yet-serving HTTP server, and the token it expects.

    Returned unstarted so a caller — a test, a supervisor — decides the
    thread it runs on. `port=0` asks the operating system for a free one,
    which is what makes this testable without a fixed port.
    """
    from thot.mcp_server import Server

    secret = token or read_or_make_token()
    mapped = Server(Path(root).resolve())
    handler = _handler_class(mapped, secret, threading.Lock())
    return _Quiet((host, port), handler), secret


def serve(root: Path | None = None, *, host: str = LOOPBACK,
          port: int = DEFAULT_PORT) -> int:
    """Run until interrupted. The URL and token are printed for the wiring."""
    import sys

    root = Path(root or os.environ.get("THOT_ROOT") or Path.cwd()).resolve()
    httpd, secret = build(root, host=host, port=port)
    bound = httpd.server_address[1]
    print(f"[thot-mcp] http://{host}:{bound}{ENDPOINT} — racine {root}",
          file=sys.stderr, flush=True)
    print(f"[thot-mcp] jeton dans {token_file()}", file=sys.stderr, flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()
    del secret
    return 0


def endpoint_answers(url: str, token_path: Path | None = None,
                     *, timeout: float = 2.0) -> bool:
    """Whether something is actually listening there, and it is this server.

    A configuration entry naming a port is not a connection. Prime cannot
    start the server itself — that is the price of the HTTP transport — so
    the difference between "wired" and "working" is whether a process is
    running right now, and only asking finds out.

    Deliberately short: this runs inside `thot fusion`, where a two-second
    pause is already more than the answer is worth.
    """
    import httpx

    try:
        secret = (token_path or token_file()).read_text(encoding="utf-8").strip()
    except OSError:
        return False
    try:
        answer = httpx.post(
            url, timeout=timeout,
            headers={"Authorization": f"Bearer {secret}"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        )
    except Exception:
        return False
    if answer.status_code != 200:
        return False
    try:
        named = answer.json()["result"]["serverInfo"]["name"]
    except (ValueError, KeyError, TypeError):
        return False
    return named == "thot"
