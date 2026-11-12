/**
 * The text up to its first full stop, for a description folded to a head.
 *
 * An abbreviation is no end of a sentence: "e.g. gpt-4o-mini" folded after
 * "e.g." left a head that stopped on its own example. Text with no sentence
 * end is returned whole.
 */
const ABBREVIATION = /(?:^|[\s(,;])(?:e\.g|i\.e|vs|cf)\.$/i;

export function firstSentence(text: string): string {
  const ends = /[.!?](?=\s|$)/g;
  for (let m = ends.exec(text); m; m = ends.exec(text)) {
    const head = text.slice(0, m.index + 1);
    if (!ABBREVIATION.test(head)) return head;
  }
  return text;
}
