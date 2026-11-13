### Changed

- **The Windows job runs two more shards.** Besides `tests/unit/scripts`, `tests/unit/tools` and `tests/unit/pipeline`, the Platforms workflow runs `tests/unit/servers` with `tests/unit/analysis`, and the top-level `tests/unit/test_*.py` files, on Windows with Python 3.13, side by side with the others. A test marked `posix` is deselected, as before. The job is not a required check.
