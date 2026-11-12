import { describe, expect, it } from "vitest";
import { countLabel, pluralNoun } from "@/lib/report-utils";

describe("a count and its noun agree", () => {
  it("pluralises regular nouns by their ending", () => {
    expect(pluralNoun("domain")).toBe("domains");
    expect(pluralNoun("entry")).toBe("entries");
    expect(pluralNoun("key")).toBe("keys");
    expect(pluralNoun("match")).toBe("matches");
    expect(pluralNoun("class")).toBe("classes");
    expect(pluralNoun("index")).toBe("indexes");
  });

  it("counts one, many and none", () => {
    expect(countLabel(1, "domain")).toBe("1 domain");
    expect(countLabel(4, "domain")).toBe("4 domains");
    expect(countLabel(0, "entry")).toBe("0 entries");
    expect(countLabel(2, "analysis", "analyses")).toBe("2 analyses");
  });
});
