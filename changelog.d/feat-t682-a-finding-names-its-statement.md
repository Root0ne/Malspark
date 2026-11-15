### Added

- **A finding of a report round names the statement it is about.** A narrative, composer, question-round or agreement-round finding carries `statements`, value-free places in the checked answer (`key_findings.1`, `body#2`, `items.3.value`, `*` for the whole answer), built from the schema's field names and list positions, in the replay record and in the run summary's unresolved rows. A finding's words, codes and count are unchanged, a row stored without the field is read as before, and the printed replay shows the places only with `--show-text`.
