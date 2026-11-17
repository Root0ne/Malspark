### Fixed

- **A TECHNIQUE line that opens with NONE and names no technique id claims none, and a claim
  heading that describes deleting code withdraws nothing.** A line that opens with NONE and
  names no technique id anywhere is read as no technique, whatever note follows it; the line
  as written stays on the claim as `technique_note`, and no question is asked about it. A
  line that opens with NONE and names an id, and a line that puts an id first and a doubt
  after it, are read as before. On a claim heading line of a validation retry, a word of withdrawing,
  removing, dropping or deleting is a withdrawal only in the clause that writes a claim
  number; a sentence end, a semicolon or a bracket ends a clause. Withdraw or retract in the
  heading's sentence, a withdrawing word in its note, a bare "Removed" opening it and the
  `WITHDRAW CLAIM` and `WITHDRAW FINDING` lines are read as before.
