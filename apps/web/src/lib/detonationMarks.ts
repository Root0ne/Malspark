/**
 * Under which detonation of the sample a row was observed, as the console says it.
 *
 * The report marks each row a further detonation observed with `observed_in`
 * (`reporting.detonation_marks`): every detonation that observed it, `d1` for
 * the job's own and `d2`, `d3`… for each one an agent asked for, with the
 * launch arguments it was made with. The console reads that mark and nothing
 * else, and words it as the report does: "observed in detonation 2, launched
 * with `…`", the job's own named where a further one observed the row too. A
 * row with no mark, as in a run with one detonation, says nothing.
 *
 * A launch text is text an agent chose, and may come from the sample: it is
 * written out by the report's own rule (`launchText`, the report's
 * `detonation_marks.launch_text`), and a mark is handed out in parts, never as
 * one joined string, so a launch text can never read as another detonation.
 * One fixture of cases, written from the report's function, holds both to the
 * same written form (`tests/fixtures/reporting/launch_text_cases.json`).
 */

import type { ObservedIn } from "@/types/malware-report";

/** The longest launch text the report writes (`detonation_marks.LAUNCH_TEXT_CHARS`), in code points. */
export const LAUNCH_TEXT_CHARS = 200;

/** The mark a cut text ends with (`utils.marked_cut.CUT_MARK`). */
const CUT_MARK = "…";

/** The job's own detonation, as a mark names it (`ledger_projection.FIRST_DETONATION`). */
const FIRST_DETONATION = "d1";

/** A further detonation's name in the one form the report reads (`sandbox_sections.QUALIFIER_RE`). */
const LATER_DETONATION_RE = /^d(?:[2-9]|[1-9]\p{Nd}{1,2})$/iu;

/** A character Python's `str.isprintable` refuses: every control, format, private-use,
 *  unassigned and separator character but the space. */
const UNPRINTABLE_RE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}]/u;

/** How the pack writes a line break and a tab (`utils.written_forms.PACK_ESCAPES`). */
const PACK_ESCAPES: Record<string, string> = { "\n": "\\n", "\r": "\\r", "\t": "\\t" };

/** A ledger id's underscore where a reader would begin one (`schemas.evidence.ENTRY_ID_JOIN_RE`). */
const ENTRY_ID_JOIN_RE = /(?:(?<![\p{L}\p{N}_])|(?<=\\[ntr"])|(?<=\\x[0-9a-f]{1,6}))ev_(?=\p{Nd})/giu;

/** The platform's run-state markers (`utils.written_forms._RUN_STATE_MARKER_RE`). */
const RUN_STATE_MARKER_RE = /(?<!=)(={3,})(\s*(?:end\s+)?run\s+state(?![\p{L}\p{N}_])[^=\n]*)(=*)/giu;

/** A sandbox item id (`analysis.sandbox_sections.ITEM_ID_RE`), whose colon is written out. */
const ITEM_ID_RE = new RegExp(
  String.raw`(?<![\p{L}\p{N}_./\\@:\-?#&=%])(?:d(?:[2-9]|[1-9]\p{Nd}{1,2})/)?` +
    String.raw`(?:proc:(?:\p{Nd}{1,20}(?:\.\p{Nd}{1,9})?|p\p{Nd}{1,9})` +
    String.raw`|(?:call|file|reg|net|sig|drop|mutex|cmd|svc|event|apistat|chan|shot|ext|rapi|alert|dump|cape):\p{Nd}{1,12})` +
    String.raw`(?![\p{L}\p{N}_:]|\.\p{Nd})`,
  "giu",
);

/** What a launch text may not hold as it is on any surface (`detonation_marks._INERT`). */
const INERT: Record<string, string> = {
  "`": "\\x60",
  "<": "\\x3c",
  ">": "\\x3e",
  "|": "\\x7c",
  "{": "\\x7b",
  "}": "\\x7d",
};

function escaped(ch: string): string {
  const code = ch.codePointAt(0) ?? 0;
  return PACK_ESCAPES[ch] ?? `\\x${code.toString(16).padStart(2, "0")}`;
}

/**
 * A further detonation's launch arguments as every surface writes them: the
 * report's `detonation_marks.launch_text`, character for character. On one
 * line, its control, separator and bidi characters written as escapes, ledger
 * ids, run-state markers and template tokens written out, each back-tick,
 * angle bracket, brace and table pipe written as its escape, the colon of a
 * sandbox item id too, and cut after all that, by code point, at
 * `LAUNCH_TEXT_CHARS` with the cut mark.
 */
export function launchText(arguments_: unknown): string {
  let text = Array.from(String(arguments_ ?? ""), (ch) => (ch !== " " && UNPRINTABLE_RE.test(ch) ? escaped(ch) : ch)).join("");
  text = text.replace(ENTRY_ID_JOIN_RE, (found) => `${found.slice(0, -1)}\\x5f`);
  if (text.includes("=")) {
    text = text.replace(RUN_STATE_MARKER_RE, (_all, rule: string, words: string, end: string) =>
      "-".repeat(rule.length) + words + "-".repeat(end.length),
    );
  }
  text = text.split("<|").join("\\x3c|").split("|>").join("|\\x3e");
  text = text.replace(ITEM_ID_RE, (found) => found.split(":").join("\\x3a"));
  const points = Array.from(text, (ch) => INERT[ch] ?? ch).join("");
  const chars = Array.from(points);
  if (chars.length <= LAUNCH_TEXT_CHARS) return points;
  return chars.slice(0, LAUNCH_TEXT_CHARS - CUT_MARK.length).join("").replace(/\s+$/u, "") + CUT_MARK;
}

/** One detonation of a mark: its name in words, and a further one's launch text as written. */
export interface MarkPart {
  /** "the job's own detonation", or "detonation 2". */
  detonation: string;
  /** A further detonation's launch text, written out (`launchText`); `null` for the job's own. */
  launch: string | null;
}

/** A row's mark in parts, one per detonation it names, or `null` where it names none. */
export function observedParts(marks: readonly ObservedIn[] | null | undefined): MarkPart[] | null {
  const parts: MarkPart[] = [];
  for (const mark of marks ?? []) {
    const name = String(mark?.detonation ?? "");
    if (name === FIRST_DETONATION) {
      parts.push({ detonation: "the job's own detonation", launch: null });
    } else if (LATER_DETONATION_RE.test(name)) {
      parts.push({ detonation: `detonation ${name.slice(1)}`, launch: launchText(mark.launched_with) });
    }
  }
  return parts.length ? parts : null;
}

/** A mark's parts in the report's words, each launch text in a code span: what a hover shows. */
export function observedTitle(parts: readonly MarkPart[]): string {
  const said = parts.map((part) =>
    part.launch === null ? part.detonation : `${part.detonation}, launched with \`${part.launch}\``,
  );
  return `observed in ${said.join(" and in ")}`;
}
