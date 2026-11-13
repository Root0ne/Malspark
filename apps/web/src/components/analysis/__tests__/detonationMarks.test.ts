/**
 * What a later detonation observed is marked beside it on the Indicators,
 * ATT&CK and Behaviour tabs (T-679): the detonation and the launch it was made
 * with, read from the report's `observed_in` and never worked out again. The
 * launch text is cut at the report's bound, with the whole text on hover; a row
 * with no mark, as in a run with one detonation, draws none.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({ useParams: () => ({ id: "J1" }) }));

import type { ReportDetailDTO } from "@/lib/api";
import { LAUNCH_TEXT_CHARS, launchShown, observedWords } from "@/lib/detonationMarks";
import type { MalwareReport, ObservedIn } from "@/types/malware-report";
import { AnalysisContext } from "../AnalysisContext";
import IocBrowser from "../IocBrowser";
import AttackContent from "../tabs/AttackContent";
import { BehavioursBlock } from "../tabs/DynamicContent";

const ARGS = "-p hunter2";
const D1: ObservedIn = { detonation: "d1" };
const d2 = (launched_with: string): ObservedIn => ({ detonation: "d2", launched_with });
const HOSTILE = "a`b|c\nd\"e'<script>alert(1)</script>{{t}} " + "Z".repeat(5000);

function iocHtml(marks: ObservedIn[] | undefined): string {
  const mr = {
    consolidated_iocs: [
      {
        type: "Domain",
        kind: "domain",
        value: "pay.example.org",
        source: "sandbox",
        published: "yes: the sandbox recorded it",
        ...(marks ? { observed_in: marks } : {}),
      },
    ],
  } as unknown as MalwareReport;
  return renderToStaticMarkup(createElement(IocBrowser, { mr }));
}

function attackHtml(marks: ObservedIn[] | undefined): string {
  const mapping = {
    technique_id: "T1486",
    technique_name: "Data Encrypted for Impact",
    tactic: "TA0040",
    evidence_quotes: [],
    confidence: null,
    contributing_layers: ["dynamic"],
    is_corroborated: false,
    ...(marks ? { observed_in: marks } : {}),
  };
  const report = {
    id: "R1",
    malware_report: { ttp_mappings: [mapping] },
    mitre_techniques: [mapping],
  } as unknown as ReportDetailDTO;
  return renderToStaticMarkup(
    createElement(
      AnalysisContext.Provider,
      { value: { jobId: "J1", report, job: null, loading: false, reportError: null, showEvidence: null } },
      createElement(AttackContent, { empty: false }),
    ),
  );
}

function behaviourHtml(marks: ObservedIn[] | undefined): string {
  const extra = marks ? { observed_in: marks } : {};
  const report = {
    malware_report: {
      dynamic: {
        process_tree: [],
        registry_mods: [],
        notable_apis: [],
        file_operations: [{ operation: "write", path: "C:\\u\\README.txt", ...extra }],
        sandbox_signatures: [
          { name: "ransomware_files", description: "", severity: 3, technique_ids: ["T1486"], marks: [], ...extra },
        ],
      },
    },
    agent_findings: [],
    run_summary: null,
  } as unknown as ReportDetailDTO;
  return renderToStaticMarkup(
    createElement(BehavioursBlock, { report, view: "all", tactics: new Map<string, ReadonlySet<string>>() }),
  );
}

const TABS: Record<string, (marks: ObservedIn[] | undefined) => string> = {
  Indicators: iocHtml,
  "ATT&CK": attackHtml,
  Behaviour: behaviourHtml,
};

describe("the words of a mark", () => {
  it("names a later detonation and its launch, and the job's own where it observed the row too", () => {
    expect(observedWords([d2(ARGS)])?.full).toBe(`observed in detonation 2, launched with ${ARGS}`);
    expect(observedWords([D1, d2(ARGS)])?.full).toBe(
      `observed in the job's own detonation and in detonation 2, launched with ${ARGS}`,
    );
  });

  it("is nothing for no mark, or for a mark naming no detonation", () => {
    expect(observedWords(undefined)).toBeNull();
    expect(observedWords([])).toBeNull();
    expect(observedWords([{ detonation: "x9" }])).toBeNull();
  });

  it("cuts a launch text at the report's bound, with the cut shown", () => {
    const shown = launchShown(HOSTILE);
    expect(shown.length).toBeLessThanOrEqual(LAUNCH_TEXT_CHARS);
    expect(shown.endsWith("…")).toBe(true);
    expect(launchShown(ARGS)).toBe(ARGS);
  });
});

describe.each(Object.keys(TABS))("the %s tab", (tab) => {
  const html = TABS[tab];

  it("marks what a later detonation observed with the detonation and its launch", () => {
    const out = html([d2(ARGS)]);
    expect(out).toContain("detonation 2");
    expect(out).toContain(`title="observed in detonation 2, launched with ${ARGS}"`);
  });

  it("draws no mark where only the job's own detonation observed it", () => {
    expect(html(undefined)).not.toContain("detonation");
  });

  it("writes a hostile launch text as text, cut, with the whole text on hover", () => {
    const out = html([d2(HOSTILE)]);
    expect(out).not.toContain("<script>");
    expect(out).toContain("&lt;script&gt;");
    // The whole text, escaped, is on the title; the drawn text holds no more than the cut.
    expect(out).toContain(`title="observed in detonation 2, launched with a\`b|c`);
    expect(out).toContain("Z".repeat(5000));
    const drawn = out.replace(/title="[^"]*"/g, "");
    expect(drawn).not.toContain("Z".repeat(LAUNCH_TEXT_CHARS));
    // A tab that draws the launch text draws it cut; a compact mark draws the detonation alone.
    if (drawn.includes("ZZZ")) expect(drawn).toContain("…");
  });
});
