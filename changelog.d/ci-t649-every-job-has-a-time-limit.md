### Changed

- **Every workflow job has a time limit sized from its measured duration (T-649).** A hung step used to hold a pull request for GitHub's default six hours. Each job now stops at no less than twice the longest run seen over the last twenty successful runs, and the E2E job's browser install is cut at ten minutes and tried a second time before the job fails. A test fails the suite if a job is added without a limit.
