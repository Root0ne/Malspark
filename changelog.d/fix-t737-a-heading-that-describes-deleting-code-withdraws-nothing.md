### Fixed

- **A claim heading that describes deleting code withdraws nothing.** On a claim heading line
  of a validation retry, the text after the heading is read a sentence at a time; a bracket, a
  semicolon and a period inside a token end no sentence. A word of withdrawing, removing,
  dropping or deleting counts as a withdrawal the reader cannot read where its own sentence
  writes a claim number or the sentence right before it does, and the retry is then asked for
  again as a whole answer. A deleting sentence with no claim number in it or in the sentence
  before describes a claim. Withdraw or retract in the heading's sentence, a withdrawing word in
  its note and a bare "Removed" opening it are doubts wherever they stand; the `WITHDRAW CLAIM`
  and `WITHDRAW FINDING` lines are read by their form.
