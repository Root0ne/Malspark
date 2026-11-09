### Added

- **One setup command for Windows, macOS and Linux.** `uv run --no-project python scripts/dev/malspark_dev.py`
  runs `setup`, `external`, `env init`, `doctor` and the stack commands (`up`, `down`, `logs`,
  `docker-up`, `docker-build`, `migrate`, `create-admin`, ...) from native PowerShell as from a
  POSIX shell. It uses the standard library only, so installing the stack syncs none of the
  project's dependencies on the host. The make targets of the same names call it.
- **`env init` writes `docker/.env` and `bootstrap.env`.** Each secret the examples leave empty
  is generated, both files carry the same database password, settings key and JWT secret, and
  `DATABASE_URL` names the port the stack publishes Postgres on. An existing file is left as it
  is; `--force` rewrites it and keeps every value it set. No secret is printed.
- **`doctor` says what the host lacks for the stack.** Docker in Linux-containers mode, the
  Compose plugin, free ports, the fetched trees and corpora, the machine's architecture, and a
  checkout on NTFS.

### Changed

- **`external` fetches `ik_llama.cpp` only when it is named** (`external ik_llama.cpp`); the
  stack does not need it.
- **Postgres is published on host port 5433 by every stack command**, the port
  `bootstrap.env`'s `DATABASE_URL` names, unless `POSTGRES_PORT` says otherwise.

### Upgrading

- A host process that reached the development stack's Postgres on 5432 reaches it on 5433 after
  the next `dev-up`; set `POSTGRES_PORT=5432` in `docker/.env` to keep the old port.
- `scripts/dev/fetch_external.sh` and `scripts/dev/fetch_capa_data.sh` are replaced by
  `malspark_dev.py external`.
