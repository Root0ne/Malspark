/**
 * Under which detonation of the sample a row was observed, as the console says it.
 *
 * The report marks each row a further detonation observed with `observed_in`
 * (`reporting.detonation_marks`): every detonation that observed it, `d1` for
 * the job's own and `d2`, `d3`… for each one an agent asked for, with the
 * launch arguments it was made with. The console reads that mark and nothing
 * else, and words it as the report does: "observed in detonation 2, launched
 * with …", the job's own named where a further one observed the row too. A row
 * with no mark, as in a run with one detonation, says nothing.
 */

import type { ObservedIn } from "@/types/malware-report";

/** The longest launch text the report writes (`detonation_marks.LAUNCH_TEXT_CHARS`). */
export const LAUNCH_TEXT_CHARS = 200;

const CUT_MARK = "…";

/** A detonation's name in the one form the report writes: `d1`, or `d2`…`d999`. */
const DETONATION_RE = /^d(?:1|[2-9]|[1-9]\d{1,2})$/i;

/** A launch text cut at the report's bound, the cut shown inside it (`marked_cut`). */
export function launchShown(text: string): string {
  const value = String(text ?? "");
  if (value.length <= LAUNCH_TEXT_CHARS) return value;
  return value.slice(0, LAUNCH_TEXT_CHARS - CUT_MARK.length).trimEnd() + CUT_MARK;
}

export interface ObservedWords {
  /** The whole mark, every launch text whole: what a hover shows. */
  full: string;
  /** The mark with each launch text cut at the report's bound: what is drawn. */
  shown: string;
  /** The detonations alone ("detonation 2"): what a compact mark draws. */
  detonations: string;
}

/** A row's mark in words, or `null` where it states no detonation. */
export function observedWords(marks: readonly ObservedIn[] | null | undefined): ObservedWords | null {
  const full: string[] = [];
  const shown: string[] = [];
  const named: string[] = [];
  for (const mark of marks ?? []) {
    const name = String(mark?.detonation ?? "").toLowerCase();
    if (!DETONATION_RE.test(name)) continue;
    if (name === "d1") {
      for (const list of [full, shown, named]) list.push("the job's own detonation");
      continue;
    }
    const detonation = `detonation ${name.slice(1)}`;
    const launch = String(mark.launched_with ?? "");
    full.push(`${detonation}, launched with ${launch}`);
    shown.push(`${detonation}, launched with ${launchShown(launch)}`);
    named.push(detonation);
  }
  if (full.length === 0) return null;
  const said = (parts: string[]) => `observed in ${parts.join(" and in ")}`;
  return { full: said(full), shown: said(shown), detonations: said(named) };
}
