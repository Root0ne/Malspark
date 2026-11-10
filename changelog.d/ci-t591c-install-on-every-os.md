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
- **On any host, a path in Windows form is masked too.** In a lost tool's reason or a rule
  file's load error, a drive path (`C:\Users\...`, `D:/...`, with single or doubled
  backslashes, as an OSError prints its file name), a UNC path (`\\server\share\...`,
  `\\10.0.0.1\c$\...`), a device, volume or long path (`\\?\C:\...`, `\\.\...`,
  `\\?\Volume{...}\...`) and a `file:///C:/...` URL are shown as "a path outside the
  project", every name a Windows file name may hold included: any character Windows allows in
  one (`$Recycle.Bin`, `a(b)`, `alice's`, `OneDrive – Firma`, `a€b`, an accent written as a
  combining mark, an emoji, a space, no-break space or thin space inside a directory's name),
  wherever the path stands: after any character but an ASCII letter or digit (`日本C:\...`,
  `path:C:\...`, `a.C:\...`), quoted in `'`, `"`, backticks, `‘’`, `“”` or `«»`, or inside a
  JSON string, which still reads as JSON once masked. A quoted Windows path is masked up to
  its closing quote, spaces and all, and a quoted span holding a second path is masked whole.
  A `file://host/...` URL (also `file:////host/...` and `file:\\host\...`, the scheme in any
  case) names a path on another machine and is masked too. The host's home directory written in a text
  (a Windows one with single, doubled or forward separators, in any case) is one path with
  every space in its name, and the path after it is read as any other. capa's
  rules directory in the reason it did not run is masked as the one path it is, whatever its
  name holds. A path inside a Windows checkout is shown from the project root
  (`data/capa-rules`), as on Linux and macOS, and any text is masked in time linear in its
  length. The words alone decide, never the host, so on a Linux host too, text without a
  Windows-form path or the home directory reads as before, and these read as one and are
  masked: `x:\d+`; a doubled backslash before a word (`\\d+\\s`, `'\\powershell.exe'`),
  read as a UNC path; a guest's path in a lost tool's reason (`'C:\Windows\System32\cmd.exe'`);
  a quoted span starting with a Windows path, up to its closing quote; and a `file://host/...`
  URL.
- **The rule replay runs on Windows, and reaches no network there either.** The replay's
  network guard lets through the one loopback connection the event loop's socket pair is made
  with where the system has no native pair, and also refuses the connections and datagrams
  Windows' event loop makes through its I/O completion port, and its named-pipe connections.
  A socket method the host lacks (`sendmsg` on Windows) is no longer listed as a door the
  replayed tree lacks.

### Documentation

- **Supported systems** in the README and the quick start: Windows (native PowerShell with
  Docker Desktop), macOS and Linux, with the CI matrix that installs on each.
