### Fixed

- **`redact_url` costs time linear in the length of its text (T-688).** A URL's scheme is looked for once per run of letters, digits, `+`, `.` and `-`, from the run's first letter, so one long line, a token or a dotted name is read once. Its output equals the output of the per-character scheme pattern on every input.
