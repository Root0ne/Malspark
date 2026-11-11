### Fixed

- **A hash constant's rule comment names the set its row was resolved in (T-647).** The comment a detection rule prints for an API-hash constant said "a function-name hash" for every row, also for a value resolved against module names. It now reads `a name hash (set modules: kernel32.dll)` or `a name hash (set exports: MessageBoxA)` in the tool's own words, several sets are listed once each in a stable order, and a row that states no set, such as one stored by an older run, reads `a name hash (MessageBoxA)`. The `api_hash_resolution` declaration carries the set as the fact `set`.
