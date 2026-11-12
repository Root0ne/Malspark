### Added

- **A finished run records the environment it ran in (T-668).** The run summary carries an `environment` block, wherever the summary is stored, served and exported: the worker's host (operating system and release, machine type, processor model, logical processors, total memory), and per agent what each model of its list sent with every request — the sampling parameters read off the model the provider built, or the statement that none was sent and the provider's default applied; the effort level with the setting it came from, or why none was sent — beside each model identifier the provider's answers named. Each fact appears only where it was read; a summary stored without the block reads as before.

### Fixed

- **The model build log line states the sampling actually sent (T-668).** It used to print the temperature handed to the provider, which a model documented to refuse sampling parameters is never sent. The line now names the sampling read off the built model, after the provider has decided.
