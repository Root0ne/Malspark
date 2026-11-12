### Added

- **The agreement between blind scorers is computed by code.** `python scripts/blind/run.py agreement SHEET SHEET ...` reads two or more filled score sheets or key scores and prints the percentage agreement, Cohen's and linear weighted kappa per pair, Fleiss' kappa, Krippendorff's alpha (nominal and ordinal, with missing ratings), each pair's confusion matrix and disagreements, for the five verdicts and for credited against not credited; `--json` prints it as data and `--leave-out-wrong` leaves `wrong` out of the ordinal statistics and counts it.
