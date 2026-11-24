/**
 * A value cell's sentence the agreement round kept as written on its quote, as the console marks it.
 *
 * Where the round's check refused a kept closing sentence only on the words of what it denies,
 * and its quote stands whole in one sentence of a section 5 passage, the sentence stands as the
 * report model wrote it, recorded under `agreement.kept_on_its_quote`
 * (`section_agreement.KEPT_ON_ITS_QUOTE_CODE`). Every surface printing such a sentence prints the
 * platform's mark beside it, in one set of words (`section_agreement.KEPT_ON_ITS_QUOTE_MARK`),
 * drawn from the run's own records when it is shown: the report document holds no field of them.
 * The console prints the value cells (a channel's protocol, encryption and packet layout; the
 * encryption scheme's cipher, mode, library and IV), so it reads the records as the report does
 * (`kept_on_its_quote_named`, `holds_kept`) and marks a cell after its text; a cell that holds
 * none of the sentence its record names carries nothing. One fixture of cases,
 * written from the report's functions, holds both to the same answers
 * (`tests/fixtures/reporting/kept_on_its_quote_cases.json`).
 */

import type { MalwareReport } from "@/types/malware-report";

/** The code a sentence kept as written on its quote is recorded under. */
export const KEPT_ON_ITS_QUOTE_CODE = "agreement.kept_on_its_quote";

/** The mark's words (`section_agreement.KEPT_ON_ITS_QUOTE_MARK`). */
export const KEPT_ON_ITS_QUOTE_MARK =
  "kept as the report model wrote it; the report's check did not agree to it: the quote " +
  "given for it, from the report's technical analysis as the check read it, holds too few " +
  "of the words of what the sentence denies; the bundle lists the quote";

/** The longest text a record holds uncut (`events.FINDING_VALUE_LIMIT`), in code points. */
export const FINDING_VALUE_LIMIT = 200;

/** The mark a cut text ends with (`utils.marked_cut.CUT_MARK`). */
const CUT_MARK = "\u2026";

/** The refusal the record names (`section_agreement.KEEP_UNQUOTED_CODE`). */
const KEEP_UNQUOTED_CODE = "agreement.keep_unquoted";

/** How the record opens, names its source and ends (`section_agreement._KEPT_HEAD` and the rest). */
const KEPT_HEAD = "The agreement question keeps a sentence of ";
const KEPT_SOURCE = " as written on ";
const KEPT_TAIL = " stands as written.";

/** What a backslash in a literal `repr` writes stands for, and the hex widths after one. */
const LITERAL_ESCAPES: Record<string, string> = {
  "\\": "\\",
  "'": "'",
  '"': '"',
  n: "\n",
  r: "\r",
  t: "\t",
};
const LITERAL_WIDTHS: Record<string, number> = { x: 2, u: 4, U: 8 };
const HEX_DIGITS_RE = /^[0-9a-fA-F]+$/;

/** The characters Python's `str.split()` splits on and `str.rstrip()` strips (`str.isspace`). */
const WHITE_SPACE = String.raw`\t\n\v\f\r\x1c-\x1f \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000`;
const WHITE_SPACE_RE = new RegExp(`[${WHITE_SPACE}]+`, "g");
const TRAILING_SPACE_RE = new RegExp(`[${WHITE_SPACE}]+$`);

/** A text's words joined by one space, as Python's `" ".join(text.split())` writes them. */
function oneLine(text: string): string {
  return text.replace(WHITE_SPACE_RE, " ").replace(/^ | $/g, "");
}

/** How many code points a text holds, as Python's `len` counts them. */
function codePoints(text: string): number {
  return [...text].length;
}

/** The text one string literal written as `repr` writes one holds, or `null` (`_written_text`). */
export function writtenText(literal: string): string | null {
  const quote = literal[0];
  if (literal.length < 2 || (quote !== "'" && quote !== '"') || literal[literal.length - 1] !== quote) {
    return null;
  }
  const end = literal.length - 1;
  let at = 1;
  let out = "";
  while (at < end) {
    const char = literal[at];
    if (char === quote) return null;
    if (char !== "\\") {
      out += char;
      at += 1;
      continue;
    }
    const mark = at + 1 < end ? literal[at + 1] : "";
    if (mark && Object.prototype.hasOwnProperty.call(LITERAL_ESCAPES, mark)) {
      out += LITERAL_ESCAPES[mark];
      at += 2;
      continue;
    }
    const width = Object.prototype.hasOwnProperty.call(LITERAL_WIDTHS, mark) ? LITERAL_WIDTHS[mark] : 0;
    const digits = literal.slice(at + 2, at + 2 + width);
    if (!width || at + 2 + width > end || !HEX_DIGITS_RE.test(digits)) return null;
    const point = parseInt(digits, 16);
    if (point > 0x10ffff) return null;
    out += String.fromCodePoint(point);
    at += 2 + width;
  }
  return out;
}

/** The label and the sentence a record of a sentence kept on its quote names, or `null`
 *  (`section_agreement.kept_on_its_quote_named`). */
export function keptOnItsQuoteNamed(message: string): [string, string] | null {
  if (!message.startsWith(KEPT_HEAD) || !message.endsWith(KEPT_TAIL)) return null;
  const at = message.indexOf(KEPT_SOURCE, KEPT_HEAD.length);
  if (at < 0) return null;
  const body = message.slice(0, message.length - KEPT_TAIL.length);
  const refused = ` (${KEEP_UNQUOTED_CODE}): `;
  let start = body.indexOf(refused, at);
  while (start >= 0) {
    const said = writtenText(body.slice(start + refused.length));
    if (said !== null) return [message.slice(KEPT_HEAD.length, at), said];
    start = body.indexOf(refused, start + 1);
  }
  return null;
}

/** What stands before the cut mark of a bounded text, or `""` (`_cut_head`). */
function cutHead(words: string): string {
  return words.endsWith(CUT_MARK) ? words.slice(0, -CUT_MARK.length).replace(TRAILING_SPACE_RE, "") : "";
}

/** Whether a one-line text is one a record bounded to `head` and the cut mark (`_bounded_from`). */
function boundedFrom(unit: string, head: string): boolean {
  return Boolean(head) && unit.startsWith(head) && codePoints(unit) > FINDING_VALUE_LIMIT;
}

/** Whether a record's bounded copy of a label is that label (`_label_names`). */
export function labelNames(written: string, label: string): boolean {
  const said = oneLine(label);
  const head = cutHead(written);
  return written === said || (Boolean(head) && said.startsWith(head) && said.length > head.length);
}

/** Whether a value cell's printed text holds a sentence `said` names (`holds_kept`). */
export function holdsKept(text: string, said: readonly string[]): boolean {
  const shown = oneLine(String(text ?? ""));
  for (const words of said) {
    const head = cutHead(words);
    if (words && shown.includes(words)) return true;
    let at = head ? shown.indexOf(head) : -1;
    while (at >= 0) {
      if (boundedFrom(shown.slice(at), head)) return true;
      at = shown.indexOf(head, at + 1);
    }
  }
  return false;
}

/** The label the round shows a channel's value cell under (`section_agreement._channel_passages`). */
export function channelCellLabel(index: number, field: "protocol" | "encryption" | "packet_layout"): string {
  return `5. Technical analysis, channel row ${index}, ${field.replace(/_/g, " ")}`;
}

/** The label the round shows a value cell of the encryption scheme under (`_scheme_passages`). */
export function schemeCellLabel(field: "cipher" | "mode" | "library" | "iv"): string {
  return `5. Technical analysis, encryption scheme, ${field.replace(/_/g, " ")}`;
}

/** The sentences the round kept as written on their quote of the value cell `label` names, as
 *  each record writes it (`section_agreement.kept_on_its_quote`). */
export function keptOf(mr: MalwareReport | null | undefined, label: string): string[] {
  const out: string[] = [];
  for (const row of mr?.run_summary?.validation?.unresolved ?? []) {
    if (row?.code !== KEPT_ON_ITS_QUOTE_CODE) continue;
    const named = keptOnItsQuoteNamed(String(row.message ?? ""));
    if (named && labelNames(named[0], label) && named[1].trim() && !out.includes(named[1])) {
      out.push(named[1]);
    }
  }
  return out;
}

/** What a value cell the round answers under `label`, printing `text`, carries after it
 *  (`section_agreement.kept_cell_said`): the mark where it holds a sentence a record names, else
 *  `""`; a cell never carries the passage note. The report also matches a sentence in the form
 *  the record stores it, after the record's own value cleaning, which masks the operator's
 *  configured credential values the console never holds: a cell whose record went through that
 *  cleaning shows no mark here (the report does). */
export function keptCellSaid(mr: MalwareReport | null | undefined, label: string, text: unknown): string {
  const said = keptOf(mr, label);
  if (said.length === 0 || typeof text !== "string") return "";
  return holdsKept(text, said) ? KEPT_ON_ITS_QUOTE_MARK : "";
}
