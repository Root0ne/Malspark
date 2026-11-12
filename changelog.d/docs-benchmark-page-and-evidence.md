### Documentation

- **The benchmark page scores the reference run against a key of 89 facts drawn from eight public
  analyses.** The run recovers 84 of them, gets none wrong, and states 37 verified facts beyond the key.
  The page publishes the run's evidence beside it (the report, the evidence bundle, the evidence ledger,
  the STIX bundle and the ATT&CK mapping, every indicator defanged) and links the run's configuration,
  `docs/examples/profiles/all-tools-reference-run.json`, which imports through the settings import. The
  README, the docs home and the known-answer gate's example state the same numbers, and tests hold the
  numbers to one another and the published evidence to its defanging.
