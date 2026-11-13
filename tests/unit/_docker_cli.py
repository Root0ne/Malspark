"""The environment a test runs ``docker compose`` with: its own variables and where docker is.

A rendering test hands docker none of the developer's environment, so no
secret of theirs reaches the rendered file. The search path it does hand over
is the directory docker was found in, then the system's: docker is not in
``/usr/bin`` everywhere (a package manager may install it under its own
prefix). ``HOME`` is kept, because the CLI finds its plugins, compose among
them, where the configuration under it says they are. On Windows the system's
directories are under ``SystemRoot``, which is kept too: a Windows program
started without it cannot load its own libraries, and the CLI looks for its
configuration and plugins under ``USERPROFILE``, ``ProgramData`` and
``ProgramFiles``, none of which holds a secret.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Mapping

DOCKER = shutil.which("docker")
if os.name == "nt":
    _ROOT = os.environ.get("SystemRoot", r"C:\Windows")
    SYSTEM_PATH = os.pathsep.join((os.path.join(_ROOT, "System32"), _ROOT))
else:
    SYSTEM_PATH = os.pathsep.join(("/usr/bin", "/bin"))


_KEPT = ("HOME", "SystemRoot", "USERPROFILE", "ProgramData", "ProgramFiles", "ProgramW6432")


def docker_env(variables: Mapping[str, str]) -> dict[str, str]:
    """``variables``, with the search path that finds docker and the caller's ``HOME``."""
    env = dict(variables)
    env["PATH"] = os.pathsep.join((os.path.dirname(DOCKER), SYSTEM_PATH)) if DOCKER else SYSTEM_PATH
    for name in _KEPT:
        if name in os.environ:
            env[name] = os.environ[name]
    return env


def compose_stdout(command: list[str], *, env: Mapping[str, str]) -> str:
    """What ``command`` printed; a failure carries the command's own stderr and exit status."""
    done = subprocess.run(command, env=dict(env), capture_output=True, text=True)
    if done.returncode != 0:
        raise AssertionError(f"{command[:2]} exited {done.returncode}: {done.stderr.strip()}")
    return done.stdout
