### Documentation

- **Where samples and uploads live per host, and how the development stack reloads.**
  Deployment says which host keeps them on bind mounts and which on the `samples` and `uploads`
  volumes, what `MALSPARK_DATA_VOLUMES` accepts, what the entry and `doctor` print, how to read a
  file out of a volume, and what `down -v` and `--no-deps` do to them. Development describes the
  files `up` adds on macOS and Windows, the polling variables, and `COMPOSE_FILE_EXTRA`'s
  splitting on `;` on Windows. Configuration points to the host-side variables.
