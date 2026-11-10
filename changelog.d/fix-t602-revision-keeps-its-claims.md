### Fixed

- **A debate revision keeps every claim it does not write again.** A claim in force is replaced only by one block of the revision that restates it and states every address the claim names that no other block of the revision states; a claim's values spread over several of the revision's claims no longer count as a restatement. A claim whose subject the revision states nowhere stays in force whole, marked carried forward, and its values are no longer recorded as dropped. A correction that names the claim's address still replaces it; one that leaves the address out is added beside it, and a blocking line that named the claim still withdraws it by rule. `WITHDRAW CLAIM` lines work as before.

### Added

- **`scripts/replay/remerge_revisions.py` merges a stored run's revisions again**, under the previous rule and the current one, from the answers in force its log holds, and prints per analyst and round the claims each rule restated, carried, withdrew and left with dropped values, and each claim the current rule keeps in force. It reads the stored run only and calls no model.
