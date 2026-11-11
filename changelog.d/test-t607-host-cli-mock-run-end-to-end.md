### Changed

- **The host command line's mock run is exercised end to end on every operating system (T-607).** `malspark analyze <file> --mock` runs as a real subprocess in the `tests/unit/scripts` shard, which the Linux, macOS and Windows jobs all run. The test reads back the exit code, the absence of a traceback, the Markdown report, the STIX file and the evidence bundle the command writes, the typed code of every tool error the run recorded, and that nothing was written into the repository.
