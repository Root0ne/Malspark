### Added

- **The score reader takes its verdict words from a key's declared scoring rules.** A table names the verdict words from worst to best, the lowest one the totals credit and the states that leave the denominator (under adjudication, does not hold for this file, unknown); `--rules` on the benchmark `score` and `gate` commands and on blind `prepare` reads key scores and blind sheets by it. A scored run reports its own denominator and the items that left it, and a word the table does not hold is refused, naming the row and the word. Without a table the reader is unchanged.
