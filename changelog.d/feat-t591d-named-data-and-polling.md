### Added

- **Samples and uploads on named volumes on macOS and Windows.** On a host that is not Linux,
  `malspark_dev.py` starts both stacks with `docker/docker-compose.named-data.yml`, which mounts
  the `samples` and `uploads` volumes wherever the compose file bind-mounts `data/samples` and
  `data/uploads` (read-only where it does), so the files the containers write keep the Linux
  owner and mode `volume-init` hands them. A fresh `samples` volume receives the image's sample
  fixtures. Linux keeps the bind mounts. `MALSPARK_DATA_VOLUMES=1` uses the volumes on any
  host, `MALSPARK_DATA_VOLUMES=0` keeps the bind mounts on any host (for a worker run on the
  host, which writes its sample copies to `data/samples`). Before `up` or `docker-up` with the
  volumes, `data/samples` and `data/uploads` are created in the checkout as their mount points.
- **The development stack reloads on macOS and Windows.** There `up` also adds
  `docker/docker-compose.dev-polling.yml`: the API's and the worker's watchers and `next dev`
  look for changed files once a second, and the API's reload watches `src/` and `apps/api/`
  only. `MALSPARK_WATCH_POLL_MS` sets `next dev`'s polling interval in milliseconds.

### Changed

- **On Windows, `COMPOSE_FILE_EXTRA` is split on `;`**, as Compose splits `COMPOSE_FILE`
  there, so a path may hold a space. Elsewhere it is split on white space.
- **`doctor`'s warning about a checkout on NTFS** says that samples and uploads are kept on
  named volumes.

### Upgrading

- A macOS or Windows host starts with empty `samples` and `uploads` volumes: what its
  `data/samples` and `data/uploads` held stays there, and a sample is copied into the volume
  again from the object store when a job needs it. `docker compose down -v` deletes the two
  volumes with the others.
