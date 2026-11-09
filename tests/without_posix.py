"""This interpreter made to lack what only POSIX has, for the repository's own code.

Windows has no ``resource``, ``fcntl``, ``pwd``, ``grp`` or ``termios``, no
``O_NOFOLLOW`` or ``O_DIRECTORY``, no ``SIGKILL`` or ``SIGHUP``, and no
process groups or user ids. :func:`install` takes all of them away in this
process, so a Linux run can ask whether the package still imports and the
suite still collects where they are missing. The modules are refused only to
code under this repository: the standard library and the installed libraries
keep their own platform branches, which this cannot imitate. Meant for a
subprocess; nothing here is undone.
"""

from __future__ import annotations

import builtins
import os
import signal
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

# The repository's own code: what the refused modules are refused to.
OWN_CODE = tuple(str(ROOT / part) + os.sep for part in ("src", "apps", "services", "tests"))

POSIX_MODULES = frozenset({"resource", "fcntl", "pwd", "grp", "termios"})
POSIX_ATTRIBUTES: dict[Any, tuple[str, ...]] = {
    os: ("O_NOFOLLOW", "O_DIRECTORY", "getuid", "killpg", "getpgrp", "wait4", "setsid"),
    signal: ("SIGKILL", "SIGHUP"),
}


def _is_own(globals_: Any) -> bool:
    where = (globals_ or {}).get("__file__") or ""
    return str(where).startswith(OWN_CODE)


def install() -> None:
    """Refuse the POSIX modules to the repository's code and delete the POSIX names."""
    real_import = builtins.__import__

    def refusing_import(name: str, globals_: Any = None, *args: Any, **kwargs: Any) -> Any:
        if name.partition(".")[0] in POSIX_MODULES and _is_own(globals_):
            raise ModuleNotFoundError(f"No module named {name!r}", name=name)
        return real_import(name, globals_, *args, **kwargs)

    builtins.__import__ = refusing_import
    for module, names in POSIX_ATTRIBUTES.items():
        for name in names:
            if hasattr(module, name):
                delattr(module, name)


if __name__ == "__main__":
    # ``python tests/without_posix.py -c CODE`` or ``... -m MODULE ARGS``.
    install()
    sys.path[0] = str(ROOT)  # the repository, not this directory
    if sys.argv[1] == "-c":
        exec(compile(sys.argv[2], "<without_posix>", "exec"), {"__name__": "__main__"})  # noqa: S102
    else:
        import runpy

        sys.argv = sys.argv[2:]
        runpy.run_module(sys.argv[0], run_name="__main__", alter_sys=True)
