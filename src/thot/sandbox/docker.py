"""Run the repository's own code without running it as you.

Ported from Hermes Agent's `tools/environments/docker.py`, keeping the
hardening flags it arrived at and dropping the lifecycle machinery — Thot
does not need a long-lived container with file sync, it needs one command
to run and the container to be gone.

The defaults are the argument. A repository under audit is untrusted code,
so:

* **no network.** `--network none` by default. A test suite that phones
  home, exfiltrates the checkout, or pulls a second stage cannot. This is
  the single most valuable flag here and the one most likely to be
  inconvenient, which is why it is a flag and not a law.
* **the checkout is read-only.** Mounted `:ro`, with a writable overlay on
  top so builds that insist on writing still work and nothing they write
  survives.
* **no privileges to escalate to.** `--cap-drop ALL`,
  `--security-opt no-new-privileges`, non-root user, tmpfs mounted nosuid.
* **bounded.** pids, memory and CPU limits, so a fork bomb in a test
  fixture costs one container instead of the machine.

And one rule that inverts Thot's usual fail-soft habit: if the sandbox was
asked for and cannot be provided, the command does **not** run. Falling
back to the host silently would turn a safety feature into a lie.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from thot.sandbox.base import DEFAULT_TIMEOUT, Result
from thot.sandbox.local import clip

# Small, has a shell and Python, and is not something a repository can
# influence. Overridable for a repo that needs its own toolchain.
DEFAULT_IMAGE = "python:3.12-slim"

WORKDIR = "/repo"
OVERLAY = "/work"

# Hermes's own security arguments, kept verbatim in spirit.
SECURITY_ARGS = (
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--tmpfs", "/tmp:rw,nosuid,size=512m",
    "--tmpfs", "/var/tmp:rw,noexec,nosuid,size=256m",
)

# A fork bomb in a test fixture should cost one container, not the machine.
PIDS_LIMIT = "512"
MEMORY = "2g"
CPUS = "2"


def _docker() -> str | None:
    return shutil.which("docker") or shutil.which("podman")


@dataclass
class DockerSandbox:
    """One container per command, removed on exit."""

    root: Path
    image: str = DEFAULT_IMAGE
    network: bool = False
    writable: bool = False
    memory: str = MEMORY
    cpus: str = CPUS
    name: str = field(default="docker", init=False)

    def available(self) -> tuple[bool, str]:
        binary = _docker()
        if binary is None:
            return False, ("`docker` est introuvable — installe Docker Desktop "
                           "ou podman, ou lance sans `--sandbox`.")
        # `docker ps` rather than `docker info`: info exits 0 with the daemon
        # down and buries the real reason under plugin warnings and a final
        # "errors pretty printing info". `ps` fails cleanly and its stderr is
        # the sentence the user needs.
        try:
            done = subprocess.run([binary, "ps", "-q"], capture_output=True,
                                  text=True, timeout=20, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"`docker ps` a échoué : {exc}"
        if done.returncode != 0:
            detail = [line for line in (done.stderr or done.stdout or "").splitlines()
                      if line.strip()]
            return False, (detail[0].strip() if detail
                           else "le démon Docker ne répond pas")
        return True, ""

    def describe(self) -> str:
        parts = [f"conteneur {self.image}"]
        parts.append("réseau coupé" if not self.network else "réseau ouvert")
        parts.append("dépôt en lecture seule" if not self.writable
                     else "dépôt inscriptible")
        return " · ".join(parts)

    def command_line(self, command: str) -> list[str]:
        """The exact `docker run` this sandbox would execute.

        Public because it is the thing worth reviewing: a user should be
        able to read the isolation rather than trust a description of it.
        """
        binary = _docker() or "docker"
        mount = f"{self.root}:{WORKDIR}" + ("" if self.writable else ":ro")

        argv = [binary, "run", "--rm", "--init",
                "-v", mount,
                "-w", WORKDIR if self.writable else OVERLAY,
                *SECURITY_ARGS,
                "--pids-limit", PIDS_LIMIT,
                "--memory", self.memory,
                "--cpus", self.cpus,
                # Non-root, and not a user that exists in the image either:
                # nothing inside owns the mounted checkout.
                "--user", "65534:65534",
                ]
        if not self.network:
            argv += ["--network", "none"]
        if not self.writable:
            # A writable copy of the checkout, on tmpfs, gone with the
            # container. Builds that insist on writing still work; nothing
            # they write reaches the real repository.
            argv += ["--tmpfs", f"{OVERLAY}:rw,exec,size=4g"]

        argv.append(self.image)
        argv += ["sh", "-c", self._script(command)]
        return argv

    def _script(self, command: str) -> str:
        if self.writable:
            return command
        # cp -a rather than a bind: the overlay has to be a real copy for
        # the read-only mount to stay read-only.
        return f"cp -a {WORKDIR}/. {OVERLAY}/ 2>/dev/null; cd {OVERLAY}; {command}"

    def run(self, command: str, *, timeout: int = DEFAULT_TIMEOUT) -> Result:
        argv = self.command_line(command)
        try:
            done = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return Result(124, f"Commande interrompue après {timeout} s.",
                          sandbox=self.name, timed_out=True)
        except (OSError, subprocess.SubprocessError) as exc:
            return Result(125, f"Le conteneur n'a pas démarré : {exc}",
                          sandbox=self.name)

        output = clip(done.stdout + done.stderr)
        if done.returncode == 125:
            # Docker's own "could not run" code. Saying so beats letting it
            # read as the command having failed.
            output = f"Docker n'a pas pu lancer le conteneur.\n{output}"
        return Result(done.returncode, output, sandbox=self.name)

    def preview(self, command: str) -> str:
        return " ".join(shlex.quote(part) for part in self.command_line(command))
