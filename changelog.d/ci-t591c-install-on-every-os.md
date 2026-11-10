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
  file's load error, a drive path (`C:\Users\...`, `D:/...`), a UNC path (`\\server\share\...`,
  `\\10.0.0.1\c$\...`), a device, volume or long path (`\\?\C:\...`, `\\.\...`,
  `\\?\Volume{...}\...`) and a `file:///C:/...` URL are shown as "a path outside the project",
  however the text writes its backslashes: once, doubled as an OSError prints its file name or
  a JSON string writes it, or doubled again in a repr of those words. Every name a Windows file
  name may hold is masked with the path: any character Windows allows in one (`$Recycle.Bin`,
  `a(b)`, `alice's`, `.(x)`, `OneDrive – Firma`, `a€b`, an accent written as a combining mark,
  an emoji, a space, no-break space or thin space inside a directory's name), a character an
  escaped text writes as `\uXXXX`, and a name that only reads like such an escape in a path
  written as it is (`John Smith\uabcd.txt`), with its separators single, doubled, mixed with
  slashes (`C:/Users/a\b`) or written `\/`. It is masked wherever the path stands: after any
  character but an ASCII letter or digit (`日本C:\...`, `path:C:\...`, `a.C:\...`), quoted in
  `'`, `"`, backticks, `‘’`, `“”` or `«»`, or inside a text that writes another: a JSON
  document or the repr of a string is read through its escapes, each string as the words it
  writes, and written back the same way, so it still reads as that document and the words and
  lines after a path stay. A text that is one string in quotes is read both as escaped and as
  it stands, and what either reading shows is masked. A quoted Windows path or `file:` URL is
  masked up to its closing quote, spaces and all, and a quoted span holding a second path is
  masked whole; a full stop after an unquoted path stays outside it. A `file://host/...` URL
  (also `file:////host/...` and `file:\\host\...`, the scheme in any case) names a path on
  another machine and is masked too. The host's home directory written in a text (a Windows one
  with single, doubled or forward separators, in any case) is one path with every space in its
  name, and the path after it is read as any other. capa's rules directory in the reason it did
  not run is read as the one path it is, whatever its name holds: inside the project it is
  shown from the project root, and a rules directory outside the project, under any directory,
  is shown as a path outside the project. A path inside a Windows checkout is shown from the
  project root (`data/capa-rules`), as on Linux and macOS, and any text is masked in time
  linear in its length. The words alone decide, never the host, so on a Linux host too, text
  without a Windows-form path or the home directory reads as before, and these read as one and
  are masked: `x:\d+`; backslashes in pairs before a word (`\\d+\\s`, `'\\powershell.exe'`),
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
