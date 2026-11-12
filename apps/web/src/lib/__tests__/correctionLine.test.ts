import { describe, expect, it } from "vitest";
import { correctionLine } from "@/components/analysis/correctionLine";

const label = (n: number, noun: string) => `${n} ${noun}${n === 1 ? "" : "s"}`;

describe("run record correction line (WA-L8)", () => {
  it("says the report does not record it when the block is missing", () => {
    expect(correctionLine(null, label)).toMatch(/does not record/);
    expect(correctionLine({}, label)).toMatch(/does not record/);
  });
  it("says zero only when zero was recorded", () => {
    expect(correctionLine({ retries: 0 }, label)).toBe("No producer needed a correction turn.");
    expect(correctionLine({ retries: 2 }, label)).toContain("2 correction turns");
  });
  it("agrees in number and does not claim the answers were all of the wrong shape", () => {
    expect(correctionLine({ retries: 1 }, label)).toMatch(/^1 correction turn was spent/);
    expect(correctionLine({ retries: 35 }, label)).toMatch(/^35 correction turns were spent/);
    expect(correctionLine({ retries: 35 }, label)).not.toMatch(/wrong shape/);
    expect(correctionLine({ retries: 35 }, label)).toMatch(/in shape or in content/);
  });
});
