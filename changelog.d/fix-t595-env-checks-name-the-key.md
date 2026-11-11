### Fixed

- **`env init` and `doctor` name an empty secret and a stale derived value, and an unreadable env file ends in one clean line.** An existing docker/.env that holds a secret with no value, or a bootstrap.env value that no longer carries the docker/.env value it is derived from, gets one line naming the keys (never a value) and pointing to `env init --force`; a docker/.env that cannot be read, is a directory or is not UTF-8 text ends `doctor`, `up`, `docker-up` and `env init` with one line naming the path and the problem instead of a traceback (T-595).
