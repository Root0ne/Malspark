### Added

- **CI installs a fresh checkout on Linux, macOS and Windows.** The Platforms workflow runs
  `setup`, `setup --dev`, `env init` (twice: the second run leaves both files as they are),
  `doctor` and the stack commands' `--dry-run` on Ubuntu, macOS and Windows runners, each
  Windows step in PowerShell, and validates the compose files on Ubuntu. A second job runs the
  host-side unit suites (`tests/unit/scripts`, `tests/unit/tools`, `tests/unit/pipeline` and
  the checks that the package imports and the `posix` mark hold where POSIX is missing) on
  Windows with Python 3.13, every test not marked `posix` included. Neither job is a required
  check.

### Documentation

- **Supported systems** in the README and the quick start: Windows (native PowerShell with
  Docker Desktop), macOS and Linux, with the CI matrix that installs on each.
