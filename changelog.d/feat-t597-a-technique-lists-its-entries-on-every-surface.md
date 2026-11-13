### Added

- **A published technique lists the same ledger entries on every surface (T-597).** The
  capability matrix records each technique's evidence (`evidence_ids` on a matrix cell and a
  published mapping): the entries among its sources, the entries a map the judge made rests
  on, and the entries its claims and findings cite that the run issued, in ledger order. The
  Markdown ATT&CK table's Evidence column, a note in the analyst report's ATT&CK table, the
  STIX `uses` edge (`x_malspark_evidence_refs`), the MISP technique attribute's comment, the
  ATT&CK Navigator layer's comment, the ATT&CK defence rows and each `/reports/{id}/mitre` row
  (`evidence_ids`) print that set, read through one function; nothing is asked of a model for
  it. A technique no ledger entry stands behind says so on each surface: "no ledger entry" in
  a cell or comment, `x_malspark_evidence_note` on the STIX edge and `[]` in the API. The
  entries of the rules that matched a technique follow the set in the Markdown cell as "rule
  matches", and the sandbox items among its sources are named as such in the Navigator
  comment and the defence rows. A report stored before the set was recorded reads as the
  entries among a technique's sources and those its statements write.
- **A table row's id is checked against the entries the row cites (T-597).** A composed row
  that states an `id` (a command's) and cites entries is held where one cited entry holds
  the id: a number, alone or as the id's last word, where the entry's code compares it in a
  switch or an else-if ladder, any other id where the entry's text writes it whole. A row
  held by none of its cited entries while another entry of the run holds it is asked about
  once, with the rows the same entries hold, naming those entries
  (`report.id_not_in_cited_entry`); an id no entry holds is not asked here. The finding
  follows `validation.feedback`, a row kept after it is marked beside its evidence, and the
  replay of a stored run runs the same check.
