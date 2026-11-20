import { describe, expect, it } from "vitest";

import type { ReputationAnswer } from "@/types/malware-report";
import {
  carriesReputationRecords,
  countsWords,
  reputationFromRecord,
  reputationFromReport,
} from "../reputation";

/** A record as the report carries it, from a server no built-in names. */
function answer(over: Partial<ReputationAnswer> = {}): ReputationAnswer {
  return {
    v: 1,
    entry_id: "ev_0003",
    tool: "lookup_digest",
    service: "HashRep",
    malicious: 9,
    total: 40,
    labels: ["Stealer", "Loader"],
    first_seen: "2023-11-14T22:13:20Z",
    last_seen: "2026-01-02T03:04:05Z",
    link: "https://rep.invalid/s/abc",
    summary: "",
    ...over,
  };
}

describe("a recorded reputation answer", () => {
  it("is drawn from the record alone, named by its declared service", () => {
    const reputation = reputationFromRecord(answer());
    expect(reputation).toEqual({
      service: "HashRep",
      entryId: "ev_0003",
      engines: 40,
      malicious: 9,
      suspicious: null,
      labels: ["Stealer", "Loader"],
      firstSeen: "2023-11-14T22:13:20Z",
      lastSeen: "2026-01-02T03:04:05Z",
      link: "https://rep.invalid/s/abc",
      summary: "",
      counts: "malicious 9; total 40",
    });
  });

  it("counts the engines the service gave when it gave no total", () => {
    expect(reputationFromRecord(answer({ total: null, engines: 75 }))?.engines).toBe(75);
  });

  it("states the engines the service counted over its counts' total, as the report does", () => {
    expect(reputationFromRecord(answer({ total: 72, engines: 70 }))?.engines).toBe(70);
  });

  it("keeps the service's words when there are no counts", () => {
    const reputation = reputationFromRecord(
      answer({ malicious: null, total: null, labels: [], summary: "hash not known" }),
    );
    expect(reputation?.engines).toBeNull();
    expect(reputation?.summary).toBe("hash not known");
  });

  it("draws nothing for a record that established nothing", () => {
    expect(
      reputationFromRecord(answer({ malicious: null, total: null, labels: [], summary: "" })),
    ).toBeNull();
    expect(reputationFromRecord(null)).toBeNull();
  });

  it("links nowhere when the link is not a web address", () => {
    expect(reputationFromRecord(answer({ link: "javascript:alert(1)" }))?.link).toBeNull();
  });
});

describe("the counts a record holds", () => {
  const stats = {
    malicious: 0,
    failure: 2,
    timeout: 28,
    harmless: 0,
    suspicious: 0,
    undetected: 37,
    "type-unsupported": 3,
    "confirmed-timeout": 1,
  };

  it("names each count it prints and states no fraction", () => {
    const words = countsWords(
      answer({ malicious: 0, suspicious: 0, total: 71, engines: 71, stats }),
    );
    expect(words).toBe(
      "malicious 0, failure 2, timeout 28, undetected 37, type-unsupported 3, " +
        "confirmed-timeout 1; engines 71",
    );
    expect(words).not.toMatch(/\//);
    expect(words).not.toMatch(/\d+ of \d+/);
  });

  it("prints a total the answer gave and never a sum of the members", () => {
    expect(countsWords(answer({ malicious: 3, total: 60, stats: {} }))).toBe("malicious 3; total 60");
    expect(
      countsWords(answer({ malicious: 4, total: 14, stats: { malicious: 4, clean: 10 } })),
    ).toBe("malicious 4, clean 10");
  });

  it("says a flagged count the record does not hold, and nothing for a record of no counts", () => {
    expect(countsWords(answer({ malicious: null, total: null, engines: 70 }))).toBe(
      "malicious not counted; engines 70",
    );
    expect(countsWords(answer({ malicious: null, total: null, labels: [] }))).toBeNull();
  });

  it("shows the record's section under the same condition as before", () => {
    const shown = reputationFromRecord(answer({ total: null, engines: 75, stats }));
    expect(shown?.engines).toBe(75);
    // The record's flagged field differs from the object's member, and it has no
    // suspicious field beside the object's member: each member is printed.
    expect(shown?.counts).toBe(
      'malicious 9, "malicious" 0, failure 2, timeout 28, "suspicious" 0, undetected 37, ' +
        "type-unsupported 3, confirmed-timeout 1; engines 75",
    );
  });

  /** The line of a record that gave no total unless `over` gives one. */
  const words = (over: Partial<ReputationAnswer>) => countsWords(answer({ total: null, ...over }));

  it("prints two different records as two different lines", () => {
    expect(words({ malicious: 1, stats: { "harmless 3; engines": 75 } })).toBe(
      'malicious 1, "harmless 3; engines" 75',
    );
    expect(words({ malicious: 1, engines: 75, stats: { harmless: 3 } })).toBe(
      "malicious 1, harmless 3; engines 75",
    );
  });

  it("quotes a member named like a label of the line or that is no plain token", () => {
    expect(words({ malicious: 1, engines: 75, stats: { malicious: 1, engines: 70 } })).toBe(
      'malicious 1, "engines" 70; engines 75',
    );
    expect(words({ malicious: 1, total: 12, stats: { malicious: 1, total: 10 } })).toBe(
      'malicious 1, "total" 10; total 12',
    );
    for (const [name, shown] of [
      ["a,b", '"a,b"'],
      ["a;b", '"a;b"'],
      ['a"b', '"a\\"b"'],
      ["a\\b", '"a\\\\b"'],
      ["a\nb", '"a\\nb"'],
      ["a b", '"a b"'],
    ]) {
      expect(words({ malicious: 1, stats: { [name]: 2 } })).toBe(`malicious 1, ${shown} 2`);
    }
  });

  it("prints a flagged or suspicious member unless it equals a field the record has", () => {
    // [field name, field value, member value, the line] as the report's helper prints them.
    const table: [string, number | null, number, string][] = [
      ["malicious", null, 0, '"malicious" 0, harmless 5; engines 70'],
      ["malicious", null, 3, '"malicious" 3, harmless 5; engines 70'],
      ["malicious", 3, 3, "malicious 3, harmless 5; engines 70"],
      ["malicious", 0, 0, "malicious 0, harmless 5; engines 70"],
      ["malicious", 4, 3, 'malicious 4, "malicious" 3, harmless 5; engines 70'],
      ["malicious", 4, 0, 'malicious 4, "malicious" 0, harmless 5; engines 70'],
      ["suspicious", null, 0, 'malicious 1, "suspicious" 0, harmless 5; engines 70'],
      ["suspicious", null, 2, 'malicious 1, "suspicious" 2, harmless 5; engines 70'],
      ["suspicious", 2, 2, "malicious 1, suspicious 2, harmless 5; engines 70"],
      ["suspicious", 0, 0, "malicious 1, harmless 5; engines 70"],
      ["suspicious", 4, 2, 'malicious 1, "suspicious" 2, harmless 5, suspicious 4; engines 70'],
      ["suspicious", 0, 2, 'malicious 1, "suspicious" 2, harmless 5, suspicious 0; engines 70'],
    ];
    for (const [name, field, member, line] of table) {
      const flagged = name === "suspicious" ? { malicious: 1 } : { malicious: null };
      const stats = { [name]: member, harmless: 5 };
      const said = words({ ...flagged, engines: 70, stats, [name]: field });
      expect(said).toBe(line);
      expect(said).not.toMatch(/not counted/);
    }
  });

  it("draws a whole-number name first, as the parsed object orders it", () => {
    expect(words({ malicious: 1, stats: { b: 2, "10": 3, a: 4, "2": 5 } })).toBe(
      "malicious 1, 2 5, 10 3, b 2, a 4",
    );
  });

  it("leaves out a flagged or suspicious member only where it equals the record's field", () => {
    expect(words({ malicious: 5, stats: { malicious: 3, harmless: 7 } })).toBe(
      'malicious 5, "malicious" 3, harmless 7',
    );
    expect(
      words({ malicious: 1, suspicious: 4, stats: { malicious: 1, suspicious: 2, harmless: 3 } }),
    ).toBe('malicious 1, "suspicious" 2, harmless 3, suspicious 4');
    expect(
      words({ malicious: 1, suspicious: 2, stats: { malicious: 1, suspicious: 2, x: 3 } }),
    ).toBe("malicious 1, suspicious 2, x 3");
    expect(words({ malicious: null, engines: 4, stats: { malicious: 3, suspicious: 1 } })).toBe(
      '"malicious" 3, "suspicious" 1; engines 4',
    );
  });
});

describe("a report", () => {
  it("is read by its records when it carries them, the first that says something", () => {
    const report = {
      reputation: [answer({ entry_id: "ev_0001", malicious: null, total: null, labels: [] }), answer()],
    };
    expect(carriesReputationRecords(report)).toBe(true);
    expect(reputationFromReport(report)?.entryId).toBe("ev_0003");
  });

  it("with an empty list draws nothing and is not read from its ledger", () => {
    expect(carriesReputationRecords({ reputation: [] })).toBe(true);
    expect(reputationFromReport({ reputation: [] })).toBeNull();
  });

  it("stored before the records is left to the legacy reader", () => {
    expect(carriesReputationRecords({})).toBe(false);
    expect(carriesReputationRecords({ reputation: null })).toBe(false);
    expect(carriesReputationRecords(null)).toBe(false);
  });
});
