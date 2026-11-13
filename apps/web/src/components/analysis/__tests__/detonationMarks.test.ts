// @vitest-environment jsdom
/**
 * What a later detonation observed is marked beside it on the Indicators,
 * ATT&CK, Behaviour and Network tabs (T-679): the detonation and the launch it
 * was made with, read from the report's `observed_in` and never worked out
 * again. The launch text is written as the report writes it, by one rule held
 * to the report's own function through one shared fixture of cases; each
 * detonation is its own part and each launch text stands in its own isolated
 * code element, so no launch text reads as another detonation. A row with no
 * mark, as in a run with one detonation, draws none.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({ useParams: () => ({ id: "J1" }) }));

import type { ReportDetailDTO } from "@/lib/api";
import { LAUNCH_TEXT_CHARS, launchText, observedParts, observedTitle } from "@/lib/detonationMarks";
import type { MalwareReport, ObservedIn } from "@/types/malware-report";
import { AnalysisContext } from "../AnalysisContext";
import DetonationMark from "../DetonationMark";
import IocBrowser from "../IocBrowser";
import AttackContent from "../tabs/AttackContent";
import { BehavioursBlock } from "../tabs/DynamicContent";
import NetworkContent from "../tabs/NetworkContent";

const ARGS = "-p hunter2";
const D1: ObservedIn = { detonation: "d1" };
const d2 = (launched_with: string): ObservedIn => ({ detonation: "d2", launched_with });
const d3 = (launched_with: string): ObservedIn => ({ detonation: "d3", launched_with });
const HOSTILE = "a`b|c\nd\"e'<script>alert(1)</script>{{t}} \u202eRTL " + "Z".repeat(5000);
/** Launch texts written to read as a further part of the mark. */
const FORGED = ["x and in the job's own detonation", "x`, and in detonation 3, launched with `y"];

interface Case {
  input: string;
  written: string;
}
const FIXTURE = JSON.parse(
  readFileSync(join(__dirname, "../../../../../../tests/fixtures/reporting/launch_text_cases.json"), "utf-8"),
) as { bound: number; cases: Case[] };

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

function attackHtml(marks: ObservedIn[] | undefined, drawnId = "T1486"): string {
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
    mitre_techniques: [{ ...mapping, technique_id: drawnId }],
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

function networkHtml(marks: ObservedIn[] | undefined): string {
  const extra = marks ? { observed_in: marks } : {};
  const report = {
    malware_report: {
      network: {
        domains: [{ fqdn: "pay.example.org", resolved_ips: [], queried_pids: [], ...extra }],
        ips: [{ address: "198.51.100.7", port: 443, transport: "tcp", ...extra }],
        urls: [{ url: "http://pay.example.org/gate.php", method: "GET", ...extra }],
      },
    },
  } as unknown as ReportDetailDTO;
  return renderToStaticMarkup(createElement(NetworkContent, { report }));
}

const TABS: Record<string, (marks: ObservedIn[] | undefined) => string> = {
  Indicators: iocHtml,
  "ATT&CK": attackHtml,
  Behaviour: behaviourHtml,
  Network: networkHtml,
};

/** The tabs whose tables draw the whole mark, launch text included. */
const DRAWN_WHOLE = new Set(["Indicators", "Behaviour"]);

/** Every mark a page draws: the tags whose hover says a mark. */
function marksIn(html: string): Element[] {
  const doc = new DOMParser().parseFromString(`<body>${html}</body>`, "text/html");
  return Array.from(doc.querySelectorAll("[title]")).filter((el) =>
    (el.getAttribute("title") ?? "").startsWith("observed in "),
  );
}

describe("a launch text, written as the report writes it", () => {
  it("is the report's written form for every case of the shared fixture", () => {
    expect(FIXTURE.bound).toBe(LAUNCH_TEXT_CHARS);
    expect(FIXTURE.cases.length).toBeGreaterThan(10);
    for (const { input, written } of FIXTURE.cases) expect(launchText(input)).toBe(written);
  });
});

describe("the parts of a mark", () => {
  it("names a later detonation and its launch, and the job's own where it observed the row too", () => {
    expect(observedParts([D1, d2(ARGS)])).toEqual([
      { detonation: "the job's own detonation", launch: null },
      { detonation: "detonation 2", launch: ARGS },
    ]);
    expect(observedTitle(observedParts([D1, d2(ARGS)]) ?? [])).toBe(
      `observed in the job's own detonation and in detonation 2, launched with \`${ARGS}\``,
    );
  });

  it("is nothing for no mark, or for a mark naming no detonation", () => {
    expect(observedParts(undefined)).toBeNull();
    expect(observedParts([])).toBeNull();
    expect(observedParts([{ detonation: "x9" }, { detonation: "D1" }])).toBeNull();
  });
});

describe.each(Object.keys(TABS))("the %s tab", (tab) => {
  const html = TABS[tab];

  it("marks what a later detonation observed with the detonation and its launch", () => {
    const marks = marksIn(html([d2(ARGS)]));
    expect(marks.length).toBeGreaterThan(0);
    for (const mark of marks) {
      expect(mark.getAttribute("title")).toBe(`observed in detonation 2, launched with \`${ARGS}\``);
      expect(mark.querySelectorAll('[data-part="detonation"]').length).toBe(1);
    }
  });

  it("draws no mark where only the job's own detonation observed it", () => {
    expect(html(undefined)).not.toContain("detonation");
  });

  it.each(FORGED)("draws a forged launch text whole inside its own element: %s", (forged) => {
    const marks = marksIn(html([d2(forged)]));
    expect(marks.length).toBeGreaterThan(0);
    // The ATT&CK and Network tables draw the compact mark; their panels draw the whole one.
    if (DRAWN_WHOLE.has(tab)) {
      expect(marks.some((mark) => mark.querySelector('[data-part="launch"]') !== null)).toBe(true);
    }
    for (const mark of marks) {
      expect(mark.querySelectorAll('[data-part="detonation"]').length).toBe(1);
      expect(mark.getAttribute("title")).toBe(`observed in detonation 2, launched with \`${launchText(forged)}\``);
      const launch = mark.querySelector('[data-part="launch"]');
      // A compact mark draws the detonation alone.
      if (launch === null) continue;
      expect(launch.tagName).toBe("CODE");
      expect(launch.querySelector("bdi")?.textContent).toBe(launchText(forged));
      expect(mark.textContent).toBe(`observed in detonation 2, launched with ${launchText(forged)}`);
    }
  });

  it("writes a hostile launch text out and cuts it as the report does", () => {
    const out = html([d2(HOSTILE)]);
    expect(out).not.toContain("<script>");
    expect(out).not.toContain("\u202e");
    expect(out).not.toContain("Z".repeat(LAUNCH_TEXT_CHARS));
    for (const mark of marksIn(out)) {
      expect(mark.getAttribute("title")).toBe(`observed in detonation 2, launched with \`${launchText(HOSTILE)}\``);
      const launch = mark.querySelector('[data-part="launch"] bdi');
      if (launch !== null) expect(launch.textContent).toBe(launchText(HOSTILE));
    }
  });
});

describe("the whole mark", () => {
  it.each(FORGED)("stands each launch text in its own isolated code element: %s", (forged) => {
    const out = renderToStaticMarkup(createElement(DetonationMark, { marks: [D1, d2(forged), d3(ARGS)] }));
    const [mark] = marksIn(out);
    expect(Array.from(mark.querySelectorAll('[data-part="detonation"]'), (el) => el.textContent)).toEqual([
      "the job's own detonation",
      "detonation 2",
      "detonation 3",
    ]);
    const launches = Array.from(mark.querySelectorAll('code[data-part="launch"] > bdi'), (el) => el.textContent);
    expect(launches).toEqual([launchText(forged), ARGS]);
  });
});

describe("the ATT&CK tab's join", () => {
  it("reads a technique id as the report does, trimmed and in upper case", () => {
    expect(marksIn(attackHtml([d2(ARGS)], " t1486 ")).length).toBeGreaterThan(0);
  });
});

describe("the Network tab", () => {
  it("marks each domain, IP and URL a later detonation observed", () => {
    const out = networkHtml([d2(ARGS)]);
    // A host's row, the DNS name and the request each carry the mark.
    expect(marksIn(out).length).toBeGreaterThanOrEqual(4);
  });
});
