### Fixed

- **An answer whose claims open under headings the claim reader does not read is asked in the heading it reads (T-699).** When a tool loop's last message writes claim field lines (`EVIDENCE:`, `CONFIDENCE:`, `TECHNIQUE:`) and no heading the claim grammar reads, the one final-answer nudge states the heading the platform reads, `CLAIM <n>: <sentence>`, from the same constants the grammar is tested against. It is the same single turn; a message with no field line gets the nudge's words as they were.
