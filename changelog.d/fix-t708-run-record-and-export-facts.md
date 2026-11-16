### Fixed

- **The stored STIX bundle's envelope holds `type`, `id` and `objects` only (T-708).** STIX 2.1 defines a bundle by those three properties; `spec_version` belongs to each object, where every object keeps it. The stored export and the judge's stored bundle no longer add `spec_version` to the envelope; `x_` properties stay where they were.
