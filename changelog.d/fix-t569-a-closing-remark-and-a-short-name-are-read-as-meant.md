### Fixed

- **A closing `CONTRADICTIONS:` remark leaves the block above it read (T-569).** A last label whose one line is a remark on the label line itself, with no field of the block's lines, is no block of its own: the block above it is read when a line of that block holds the fields. A block ends at the next label, and a final block of its own lines is still the only one read.
- **A short name before "claim N" names the analyst holding the claim (T-569).** "STATIC claim 17" names the `static` analyst; on a line whose field leaves `static` out while its answer in force holds no claim 17, it names the one analyst of the field the form fits whose answer holds claim 17.
