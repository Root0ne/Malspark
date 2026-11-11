### Changed

- **Every workflow job has a time limit (T-649).** A hung step used to hold a pull request for GitHub's default six hours. A job that had no limit now takes one of at least twice its longest run over the last twenty successful runs; a limit that already existed is kept, or raised where it was under twice the longest run. The E2E job's browser install is cut at ten minutes and tried a second time before the job fails. A test fails the suite if a job is added without a limit.
