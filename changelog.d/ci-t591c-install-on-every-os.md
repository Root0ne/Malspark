### Added

- **CI installs a fresh checkout on Linux, macOS and Windows.** The Platforms workflow runs
  `setup`, `setup --dev`, `env init` (twice: the second run leaves both files as they are),
  `doctor` and the stack commands' `--dry-run` on Ubuntu, macOS and Windows runners, each
  Windows step in PowerShell, and validates the compose files on Ubuntu. A second job runs the
  host-side unit suites (`tests/unit/scripts`, `tests/unit/tools`, `tests/unit/pipeline` and
  the checks that the package imports, files open safely and the `posix` mark holds where
  POSIX is missing) on Windows with Python 3.13, in three shards side by side, every test not
  marked `posix` included. Neither job is a required check.

### Fixed

- **The pinned third-party trees are the same bytes on every host.** `malspark_dev.py setup`
  and `external` run git with `core.autocrlf=false` and `core.eol=lf` for every clone,
  checkout and patch, so Git for Windows' line-ending conversion no longer turns the files
  built into the Linux images into CRLF files; a tree fetched on Linux or macOS is unchanged.
- **`malspark_dev.py` prints any path on any console.** A character the console's encoding
  lacks (a Windows console piped to a file encodes in its code page) is written escaped
  instead of stopping the command with `UnicodeEncodeError`.
- **Generated files are written with LF on every host.** The validation-code page
  (`scripts/validation_codes/run.py`, also with `--stdout`) and the family fingerprint
  catalogue and its build record, whose catalogue digest now matches the file on Windows.
- **A host path in a tool's reason is masked in Windows form too.** A path such as
  `C:\Users\...` or `D:/...`, or a `file:///C:/...` URL, in a lost tool's reason or a rule
  file's load error is shown as "a path outside the project", and a path inside a Windows
  checkout is shown from the project root (`data/capa-rules`), as on Linux and macOS.
- **The rule replay runs on Windows.** The replay's network guard lets through the one
  loopback connection the event loop's socket pair is made with where the system has no
  native pair, and a socket method the host lacks (`sendmsg` on Windows) is no longer listed
  as a door the replayed tree lacks.

### Documentation

- **Supported systems** in the README and the quick start: Windows (native PowerShell with
  Docker Desktop), macOS and Linux, with the CI matrix that installs on each.
