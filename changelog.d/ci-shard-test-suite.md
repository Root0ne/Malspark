### Changed

- **The CI test suites run in shards on parallel runners.** The Linux suite is split over six runners and the macOS unit and API suites over four, by a map in `scripts/ci/shard_map.py` balanced on measured durations. A map check fails the run when the shards together do not collect exactly the tests of the whole suite, none missing and none twice, and the checks *Test Suite (Python 3.13)* and *Test Suite (macOS arm64)* keep their names and pass only when every shard and the map check passed. Each shard uploads a JUnit report from which the map is rebalanced.
