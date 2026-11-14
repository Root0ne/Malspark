### Added

- **A published technique lists the same ledger entries on every surface (T-597).** The
  capability matrix records each technique's evidence (`evidence_ids` on a matrix cell and a
  published mapping): the entries cited by the statements that name the technique (its claims
  and findings, a map the judge made, an asserting tool's own entry) that the run issued, in
  ledger order; an entry that only looked the catalogue up is in no technique's set. The
  Markdown ATT&CK table's Evidence column, a note in the analyst report's ATT&CK table, the
  STIX `uses` edge (`x_malspark_evidence_refs`), the MISP technique attribute's comment, the
  ATT&CK Navigator layer's comment, the ATT&CK defence rows and each `/reports/{id}/mitre` row
  (`evidence_ids`) print that set, read through one function; nothing is asked of a model for
  it. Each prints the sandbox items among the technique's sources beside the set, named
  apart ("sandbox items: …"; `sandbox_items` in the API). A technique whose statements cite no
  ledger entry and that has no item says so on each surface: "no ledger entry" in a cell or
  comment, `x_malspark_evidence_note` on the STIX edge and `[]` in the API. The entries of the
  rules that matched a technique follow the set in the Markdown cell as "rule matches". A
  report stored before the set was recorded reads as the entries among a technique's sources
  and those its statements write, on every surface and in the run diff, which shows the
  sandbox items beside the set.
- **A table row's id is checked against the entries the row cites (T-597).** A composed row
  that states an `id` (a command's) and cites entries is held where one cited entry holds
  the id. A number, alone or as the id's last word after a label every numbered row shares,
  is held where a cited entry writes it as a compared operand in any base and form the reader
  knows: an equality test (also inside a comment or a string), a case label or a
  `case A ... B:` range, or a compare instruction read by its shape (a mnemonic that begins
  with `cmp`, the number in either operand place, with or without `$` or `#`). A row citing
  code in a form the reader does not read, or a compare it does not take (an instruction
  operand in no form it reads, or case ranges past 4096 values in one text), is not asked.
  A table with fewer than four numbered ids, or whose numbered ids are a plain count (1 to N
  or 0 to N-1, the guard the command-value check uses as well), is not checked for its
  numbers. Any other id is held where the entry's text writes it whole. A failed call or an
  error envelope holds nothing. A row held by none of its cited entries is asked about once,
  with the rows the same entries hold, naming those entries (`report.id_not_in_cited_entry`):
  for a number, only the entries whose one compared expression holds the most of the table's
  numbers, where they agree on its values, never one that merely compares it; for any other
  id, every entry whose text writes it. An id no entry holds is not asked here. The finding
  follows `validation.feedback`, a row kept after it is marked beside its evidence, and the
  replay of a stored run runs the same check.
