### Added

- **Samples and uploads on named volumes on macOS and Windows.** On a host that is not Linux,
  `malspark_dev.py` starts both stacks with `docker/docker-compose.named-data.yml`, which mounts
  the `samples` and `uploads` volumes wherever the compose file bind-mounts `data/samples` and
  `data/uploads` (read-only where it does), so the files the containers write keep the Linux
  owner and mode `volume-init` hands them. `volume-init` fills a fresh `samples` volume with the
  image's sample fixtures before it hands the volume over, on `up` and on a `compose run` that
  starts it alike. The API and the worker read the tracked fixture directories under
  `data/samples` read-only from the checkout, so a change to them reaches the stack as on Linux.
  Linux keeps the bind mounts. `MALSPARK_DATA_VOLUMES` set to `1`, `true`, `yes` or `on` (any
  case) uses the volumes on any host, and `0`, `false`, `no` or `off` keeps the bind mounts on
  any host (for a worker run on the host, which writes its sample copies to `data/samples`);
  any other value is named in a warning and the host's choice stands. Before `up` or
  `docker-up` with the volumes, `malspark_dev.py` names the two volumes and says that the
  containers do not see a file put in `data/samples` or `data/uploads`, and creates the two
  directories in the checkout as the volumes' mount points; something other than a directory
  standing there stops the start with a `FAIL` line naming it. `doctor` says the same whenever
  the volumes are used.
- **The development stack reloads on macOS and Windows.** There `up` also adds
  `docker/docker-compose.dev-polling.yml`: the API's and the worker's watchers and `next dev`
  (through `MALSPARK_WATCH_POLL_MS` in `next.config.ts` and `WATCHPACK_POLLING`) look for
  changed files once a second, and the API's reload watches `src/` and `apps/api/` only.
  `MALSPARK_WATCH_POLL_MS` sets `next dev`'s polling interval in milliseconds.

### Changed

- **On Windows, `COMPOSE_FILE_EXTRA` is split on `;`**, as Compose splits `COMPOSE_FILE`
  there, so a path may hold a space. Elsewhere it is split on white space.
- **`doctor`'s warning about a checkout on NTFS** says that samples and uploads are kept on
  named volumes when they are, and what the bind mounts lose when `MALSPARK_DATA_VOLUMES`
  keeps them.

### Upgrading

- A macOS or Windows host starts with empty `samples` and `uploads` volumes: what its
  `data/samples` and `data/uploads` held stays there, unseen by the containers, and a sample is
  copied into the volume again from the object store when a job needs it.
  `MALSPARK_DATA_VOLUMES=0` keeps the bind mounts. `docker compose down -v` deletes the two
  volumes with the others.
- A container started with `--no-deps` before `volume-init` has run on a fresh `samples`
  volume leaves that volume owned by root, which the API and the worker cannot write, until
  `volume-init` runs; start the stack, or `volume-init`, first.
