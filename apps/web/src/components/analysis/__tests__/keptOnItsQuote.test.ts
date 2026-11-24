/**
 * A value cell holding a sentence the agreement round kept as written on its quote carries the
 * platform's mark after it on the console, in the report's words (T-881): the round's records
 * are read as the report reads them, by one set of rules held to the report's own functions
 * through one shared fixture of cases. A cell whose record names a sentence it no longer holds,
 * or a record of another end, draws nothing. Every sentence, quote and id is made up.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  FINDING_VALUE_LIMIT,
  KEPT_ON_ITS_QUOTE_MARK,
  channelCellLabel,
  holdsKept,
  keptOnItsQuoteNamed,
  labelNames,
  schemeCellLabel,
} from "@/lib/keptOnItsQuote";
import type { MalwareReport } from "@/types/malware-report";
import TechnicalAnalysisPanel from "../TechnicalAnalysisPanel";
import { technicalSubsections } from "../reportProse";

interface Fixture {
  mark: string;
  bound: number;
  records: Array<{ message: string; named: [string, string] | null }>;
  cells: Array<{ text: string; said: string[]; holds: boolean }>;
  labels: Array<{ id: string; label: string }>;
  label_pairs: Array<{ written: string; label: string; names: boolean }>;
}
const FIXTURE = JSON.parse(
  readFileSync(join(__dirname, "../../../../../../tests/fixtures/reporting/kept_on_its_quote_cases.json"), "utf-8"),
) as Fixture;

/** The text of a page outside its tags, read by a scan, with the entities React writes decoded. */
function textOf(html: string): string {
  let out = "";
  let inTag = false;
  for (const char of html) {
    if (char === "<") inTag = true;
    else if (char === ">") inTag = false;
    else if (!inTag) out += char;
  }
  return out
    .split("&#x27;").join("'")
    .split("&quot;").join('"')
    .split("&lt;").join("<")
    .split("&gt;").join(">")
    .split("&amp;").join("&");
}

/** How often the mark stands in a page's text. */
function marks(html: string): number {
  return textOf(html).split(`[${KEPT_ON_ITS_QUOTE_MARK}]`).length - 1;
}

/** The panel's text for a report. */
function panel(mr: MalwareReport): string {
  return textOf(renderToStaticMarkup(createElement(TechnicalAnalysisPanel, { report: mr })));
}

/** A record of a sentence kept as written on its quote, as the round writes one. */
function kept(label: string, sentence: string): { agent: string; code: string; message: string } {
  return {
    agent: "agreement",
    code: "agreement.kept_on_its_quote",
    message:
      `The agreement question keeps a sentence of ${label} as written on command_and_control, ` +
      "quoting 'the relay link was never keyed', which stands whole in one sentence there, " +
      "though the keep was refused only on the words of what the sentence denies something of " +
      `(agreement.keep_unquoted): '${sentence}' stands as written.`,
  };
}

const KEPT_CELL = "The relay link cipher was not identified at run time";
const KEPT_CIPHER = "No cipher name was recovered for the relay";

function report(unresolved: Array<{ agent: string; code: string; message: string }>): MalwareReport {
  return {
    technical_analysis: {
      encryption_scheme: { cipher: KEPT_CIPHER, mode: "Counter mode was named by the analysts" },
    },
    c2_channels: [
      { name: "beacon", protocol: "TCP", encryption: "Plain text", packet_layout: null, beacon_format: null, evidence_ref: null },
      { name: "relay", protocol: "UDP", encryption: KEPT_CELL, packet_layout: null, beacon_format: null, evidence_ref: null },
    ],
    run_summary: { validation: { unresolved } },
  } as unknown as MalwareReport;
}

describe("the console reads a kept sentence's record as the report does", () => {
  it("holds the mark's words, the record bound and every rule to the report's own fixture", () => {
    expect(FIXTURE.mark).toBe(KEPT_ON_ITS_QUOTE_MARK);
    expect(FIXTURE.bound).toBe(FINDING_VALUE_LIMIT);
    expect(FIXTURE.records.length).toBeGreaterThan(10);
    for (const row of FIXTURE.records) expect(keptOnItsQuoteNamed(row.message)).toEqual(row.named);
    for (const row of FIXTURE.cells) expect(holdsKept(row.text, row.said)).toBe(row.holds);
    for (const row of FIXTURE.label_pairs) expect(labelNames(row.written, row.label)).toBe(row.names);
    for (const row of FIXTURE.labels) {
      const [, index, field] = row.id.split(".");
      const label = row.id.startsWith("communications.")
        ? channelCellLabel(Number(index), field as "protocol" | "encryption" | "packet_layout")
        : schemeCellLabel(index as "cipher" | "mode" | "library" | "iv");
      expect(label).toBe(row.label);
    }
  });
});

describe("a value cell kept on its quote carries the mark", () => {
  it("marks the channel cell and the scheme cell the records name, and no other", () => {
    const mr = report([
      kept(channelCellLabel(2, "encryption"), KEPT_CELL),
      kept(schemeCellLabel("cipher"), KEPT_CIPHER),
    ]);
    const html = renderToStaticMarkup(createElement(TechnicalAnalysisPanel, { report: mr }));
    expect(marks(html)).toBe(2);
    const text = textOf(html);
    expect(text).toContain(`encryption: ${KEPT_CELL}[${KEPT_ON_ITS_QUOTE_MARK}]`);
    expect(text).toContain(`${KEPT_CIPHER}[${KEPT_ON_ITS_QUOTE_MARK}]`);
    expect(text).not.toContain(`Plain text[${KEPT_ON_ITS_QUOTE_MARK}]`);
    const scheme = technicalSubsections(mr).find((block) => block.key === "encryption_scheme");
    expect(scheme?.marked).toEqual(["Cipher"]);
  });

  it("draws nothing where the record names a sentence the cell no longer holds", () => {
    const moved = report([
      kept(channelCellLabel(2, "encryption"), "A sentence this cell does not hold."),
      kept(schemeCellLabel("cipher"), "A cipher sentence this cell does not hold."),
    ]);
    expect(panel(moved)).toBe(panel(report([])));
    expect(technicalSubsections(moved).find((block) => block.key === "encryption_scheme")).not.toHaveProperty("marked");
  });

  it("draws nothing for a record of another end, or beside a cell holding none of its record's sentence", () => {
    const other = report([
      { ...kept(channelCellLabel(2, "encryption"), KEPT_CELL), code: "agreement.dropped" },
      kept(channelCellLabel(1, "encryption"), KEPT_CELL),
    ]);
    expect(panel(other)).toBe(panel(report([])));
    expect(technicalSubsections(other).find((block) => block.key === "encryption_scheme")).not.toHaveProperty("marked");
  });
});
