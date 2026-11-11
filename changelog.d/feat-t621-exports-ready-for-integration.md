### Added

- **`GET /reports/{id}/misp-event` serves a report as one MISP event (T-621).** The event wraps the
  report's published MISP attributes with a uuid derived from the report's job, the day the report
  was built, analysis complete, distribution `0` (the receiver decides how far it shares) and an
  undefined threat level; its tags are the report's `tlp:` level, its verdict and the ATT&CK
  galaxy clusters of its published techniques, and a `file` object names the sample by its name,
  size and identity digests. The signed job package carries it as `export/misp-event.json`, and
  the console's Export menu offers it beside the attribute download.
- **Every export carries the report's TLP level (T-621).** The STIX bundle carries the level's
  TLP 2.0 marking definition, by its fixed id, and names it in `object_marking_refs` on every
  domain object and relationship; each `/iocs` row carries `tlp` (`TLP:AMBER`), and each MISP
  attribute a `tlp:` tag. The level is the one the report's cover prints.
- **An IOC row, its STIX indicator and its MISP attribute name the ledger entries behind it
  (T-621).** The IOC table's rows carry `evidence_ids`, the entries the run's record ties to them
  (an analyst's listing, a call binding, the tools that recovered a hidden value), only ids the
  ledger holds; `/iocs` serves them, the STIX indicator carries them as
  `x_malspark_evidence_refs` and a MISP attribute names them in its comment.

### Changed

- **The STIX export derives every id it writes (T-621).** Each id is derived from what identifies
  the object (the sample's SHA-256, its kind and pattern, name or relationship ends) and every
  `created`, `modified` and `valid_from` the platform writes is the time the report was built,
  so the same report renders to the same bundle and a consumer importing it again holds one
  object per object. The judge's label map names the derived ids. Stored bundles are served as
  stored; technique and producer ids are unchanged.

### Fixed

- **A rule download parses as its kind and serves the rules the report prints (T-621).**
  `signatures/{kind}` named each rule in a `//` line, which only YARA reads as a comment, and
  joined Sigma documents without `---`, so a Sigma or Suricata download did not load. Each name
  is now a comment of the kind's own syntax and Sigma documents form one YAML stream. The default
  serves the drafts the report prints, none of which fails to compile; `?include=all` serves
  every draft with its standing, and the console offers it where a draft is not printed.
