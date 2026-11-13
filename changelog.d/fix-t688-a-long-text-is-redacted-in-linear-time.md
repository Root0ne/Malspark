### Fixed

- **A long text is redacted in time linear in its length (T-688).** The URL pattern of `redact_url` read a long run of letters, digits, `+`, `.` and `-` that is no scheme (one long line, a token, a dotted name) again from each of its characters, so 20 KB took 0.2 s and 100 KB took several seconds. A scheme is looked for once per run, from its first letter, and a megabyte of any shape is redacted in about 0.1 s or less. The text returned for every input is unchanged.
