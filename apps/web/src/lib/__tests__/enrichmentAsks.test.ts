import { describe, expect, it } from "vitest";
import { enrichmentAskSentence, enrichmentAsks } from "@/lib/enrichment";
import type { EnrichmentAskRow } from "@/types/malware-report";

const row = (over: Partial<EnrichmentAskRow> = {}): EnrichmentAskRow => ({
  source: "rdap",
  host: "rdap.example.net",
  kinds: { ip: 2 },
  failed: 0,
  why: "",
  ...over,
});

describe("the enrichment asks a run recorded", () => {
  it("reads the asked rows of the disclosure record", () => {
    expect(enrichmentAsks({ disclosure: { enrichment: { asked: [row()] } } })).toHaveLength(1);
  });

  it("is empty for a run without the record, or with an odd one", () => {
    expect(enrichmentAsks(null)).toEqual([]);
    expect(enrichmentAsks({})).toEqual([]);
    expect(enrichmentAsks({ disclosure: { enrichment: { asked: "x" as never } } })).toEqual([]);
    expect(enrichmentAsks({ disclosure: { enrichment: { asked: [3 as never, row()] } } })).toHaveLength(1);
  });
});

describe("one asked source in words", () => {
  it("says nothing of failures when there were none", () => {
    expect(enrichmentAskSentence(row())).toBe("rdap: rdap.example.net about 2 ips");
  });

  it("makes every count agree with its noun", () => {
    expect(enrichmentAskSentence(row({ kinds: { domain: 4 } }))).toBe("rdap: rdap.example.net about 4 domains");
    expect(enrichmentAskSentence(row({ kinds: { domain: 1, ip: 1 } }))).toBe(
      "rdap: rdap.example.net about 1 domain, 1 ip",
    );
    expect(enrichmentAskSentence(row({ kinds: { domain: 3, ip: 2, hash: 1, url: 0 } }))).toBe(
      "rdap: rdap.example.net about 3 domains, 2 ips, 1 hash, 0 urls",
    );
  });

  it("says a transport failure may have arrived, and an error status did", () => {
    const words = enrichmentAskSentence(row({ failed: 1, errored: 2 }));
    expect(words).toContain("1 failed in transport or did not finish and may have arrived");
    expect(words).toContain("2 answered with an error status (it arrived)");
  });

  it("reads a row stored before `errored` as it was read, and names a tool server", () => {
    const words = enrichmentAskSentence(row({ host: "", failed: 1 }));
    expect(words).toBe(
      "rdap: a tool server about 2 ips (1 failed in transport or did not finish and may have arrived)",
    );
  });
});
