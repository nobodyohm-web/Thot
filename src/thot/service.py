"""Keep the MCP endpoint answering, without anybody remembering to start it.

Prime reaches Thot over HTTP because its manager drops every server whose
`type` is not `http`, and an HTTP transport is the one transport a client
cannot start for itself: Hermes spawns `thot mcp serve` and talks down the
pipe it opened, Prime dials a URL and expects someone to be there. So
`thot fusion wire` writes `http://127.0.0.1:8787/mcp` into Prime's
configuration and that address is true only while a terminal happens to be
open — a promise the program kept until the next reboot and no longer.

The unit is written, never loaded. Thot says the one command that activates
it and lets you run it, the same rule `schedule/install.py` follows: a tool
that quietly registers background agents on your machine is a tool you stop
trusting, and the copy-paste costs one line.
"""

from __future__ import annotations

import platform
import shlex
from pathlib import Path
from xml.sax.saxutils import escape

from thot.paths import log_file
from thot.schedule.install import agent_path, thot_command

LABEL = "com.thot.mcp"
LAUNCH_AGENTS = Path.home() / "Library" / "LaunchAgents"
SYSTEMD_USER = Path.home() / ".config" / "systemd" / "user"
UNIT_NAME = "thot-mcp.service"

# Long enough that a port already taken cannot become a spin. launchd
# relaunches a KeepAlive job the instant it exits, and a server that dies on
# `Address already in use` exits in milliseconds — without this the pair of
# them burn a core between them until somebody notices.
THROTTLE_SECONDS = 10


def _command(port: int) -> list[str]:
    # `thot_command`, shared with the scheduler, rather than a second copy of
    # the same fallback: the one written here spelled it `-m thot.cli`, which
    # imports the module and exits 0 without running anything. Under
    # `KeepAlive` that is not a dead server, it is a relaunch every ten
    # seconds for ever, and `/mcp` on Prime's side stays empty throughout.
    return [*thot_command(), "mcp", "serve", "--http", "--port", str(port)]


def unit_path() -> Path:
    if platform.system() == "Darwin":
        return LAUNCH_AGENTS / f"{LABEL}.plist"
    return SYSTEMD_USER / UNIT_NAME


def launchd_plist(root: Path, *, port: int = 0) -> str:
    from thot.mcp_http import DEFAULT_PORT

    port = port or DEFAULT_PORT
    root = Path(root).resolve()
    arguments = "".join(
        f"\n    <string>{escape(part)}</string>" for part in _command(port)
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>{arguments}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key><integer>{THROTTLE_SECONDS}</integer>
  <key>WorkingDirectory</key><string>{escape(str(root))}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>{escape(agent_path())}</string>
    <key>HOME</key><string>{escape(str(Path.home()))}</string>
    <key>THOT_ROOT</key><string>{escape(str(root))}</string>
    <key>PYTHONUNBUFFERED</key><string>1</string>
  </dict>
  <key>StandardOutPath</key><string>{escape(str(log_file("mcp")))}</string>
  <key>StandardErrorPath</key><string>{escape(str(log_file("mcp")))}</string>
</dict>
</plist>
"""


def systemd_unit(root: Path, *, port: int = 0) -> str:
    from thot.mcp_http import DEFAULT_PORT

    port = port or DEFAULT_PORT
    root = Path(root).resolve()
    return f"""[Unit]
Description=Thot — carte du code servie en MCP
After=default.target

[Service]
Type=simple
ExecStart={shlex.join(_command(port))}
WorkingDirectory={root}
Environment=THOT_ROOT={root}
Environment=PATH={agent_path()}
Environment=PYTHONUNBUFFERED=1
Restart=always
RestartSec={THROTTLE_SECONDS}

[Install]
WantedBy=default.target
"""


def installed() -> bool:
    """Whether the unit file is on disk. Not whether it is loaded, and not
    whether the endpoint answers — three different questions, and only the
    third one is what Prime actually needs."""
    return unit_path().exists()


def activation() -> str:
    """The one command that turns the written unit on.

    Named apart from `install` because `doctor` needs to say it about a unit
    that is already on disk: written and never loaded is the state a machine
    sits in between `thot mcp service` and the copy-paste, and telling the
    reader to install it again would be the wrong sentence.
    """
    target = unit_path()
    if platform.system() == "Darwin":
        return f"launchctl load {target}"
    return f"systemctl --user enable --now {UNIT_NAME}"


def install(root: Path, *, port: int = 0) -> tuple[Path, str]:
    """Write the unit. Returns (file written, the command that activates it)."""
    target = unit_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    if platform.system() == "Darwin":
        target.write_text(launchd_plist(root, port=port), encoding="utf-8")
    else:
        target.write_text(systemd_unit(root, port=port), encoding="utf-8")
    return target, activation()


def uninstall_hint() -> str:
    target = unit_path()
    if platform.system() == "Darwin":
        return f"launchctl unload {target} && rm {target}"
    return f"systemctl --user disable --now {UNIT_NAME} && rm {target}"


def answering(port: int = 0) -> bool:
    """Whether the endpoint Prime was given replies right now."""
    from thot.mcp_http import DEFAULT_PORT, ENDPOINT, LOOPBACK, endpoint_answers

    port = port or DEFAULT_PORT
    return endpoint_answers(f"http://{LOOPBACK}:{port}{ENDPOINT}")
