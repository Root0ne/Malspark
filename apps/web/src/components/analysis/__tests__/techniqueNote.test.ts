/**
 * A published technique's mark says what the sandbox tagged, in the report's
 * words (T-871): per detonation, its launch, the signatures that tag the
 * technique by name and the id each tags where that is not the technique's;
 * never that the behaviour was observed. The console's writer and the report's
 * (`detonation_marks.technique_words`) are held to the same text by one shared
 * fixture of cases (`tests/fixtures/reporting/technique_note_cases.json`), which
 * a Python test pins as well; a mark stored before its signatures were
 * recorded keeps the console's old words.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { techniqueWords } from "@/lib/detonationMarks";
import type { ObservedIn } from "@/types/malware-report";
import DetonationMark from "../DetonationMark";

interface Case {
  case: string;
  technique_id: string;
  observed_in: ObservedIn[];
  words: string;
}
const CASES = (
  JSON.parse(
    readFileSync(join(__dirname, "../../../../../../tests/fixtures/reporting/technique_note_cases.json"), "utf-8"),
  ) as { cases: Case[] }
).cases;

/** An attribute's text as the markup writes it, its entities read back. */
function unescaped(text: string): string {
  return text
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

function titleOf(html: string): string | null {
  const found = /title="([^"]*)"/.exec(html);
  return found ? unescaped(found[1]) : null;
}

/** The text a reader is shown: every tag dropped, entities read back. */
function textOf(html: string): string {
  return unescaped(html.replace(/<[^>]*>/g, ""));
}

describe("a technique's mark, in the report's words", () => {
  it.each(CASES.map((c) => [c.case, c] as const))("is the shared case's text: %s", (_, c) => {
    expect(techniqueWords(c.technique_id, c.observed_in)).toBe(c.words);
  });

  it.each(CASES.filter((c) => c.observed_in.some((m) => m.signatures?.length)).map((c) => [c.case, c] as const))(
    "never says observed where it lists its signatures: %s",
    (_, c) => {
      expect(c.words.toLowerCase()).not.toContain("observed");
    },
  );
});

describe("the ATT&CK tab's mark of a technique", () => {
  it.each(CASES.filter((c) => c.words).map((c) => [c.case, c] as const))(
    "hovers with the report's words and draws them: %s",
    (_, c) => {
      const html = renderToStaticMarkup(
        createElement(DetonationMark, { marks: c.observed_in, techniqueId: c.technique_id }),
      );
      expect(titleOf(html)).toBe(c.words);
      // Drawn, each launch text and name stands in its own code element without the backticks;
      // an id of another form than ATT&CK's is drawn as the hover writes it, in its backticks.
      if (c.observed_in.some((m) => m.signatures?.length) && c.case !== "an id of another form") {
        expect(textOf(html)).toBe(c.words.replace(/`([^`]*)`/g, "$1"));
        expect(html).not.toContain("<script>");
      }
    },
  );

  it("draws the detonations alone where it is compact, never saying observed", () => {
    const listed = CASES.find((c) => c.case === "two detonations, one signature");
    expect(listed).toBeDefined();
    const html = renderToStaticMarkup(
      createElement(DetonationMark, { marks: listed?.observed_in, techniqueId: listed?.technique_id, compact: true }),
    );
    expect(textOf(html)).toBe("tagged by signatures in the job's own detonation and in detonation 2");
    expect(titleOf(html)).toBe(listed?.words);
  });

  it("keeps the old words for a mark stored before its signatures were recorded", () => {
    const stored = CASES.find((c) => c.case === "a mark stored before its signatures");
    const html = renderToStaticMarkup(
      createElement(DetonationMark, { marks: stored?.observed_in, techniqueId: stored?.technique_id }),
    );
    expect(titleOf(html)).toBe(stored?.words);
    expect(stored?.words.startsWith("observed in ")).toBe(true);
  });
});
