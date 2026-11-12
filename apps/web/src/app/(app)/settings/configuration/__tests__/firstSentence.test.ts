import { describe, expect, it } from "vitest";
import { firstSentence } from "../firstSentence";

describe("the head a long description folds to", () => {
  it("ends at the first full stop", () => {
    expect(firstSentence("Sets the cap. It also does more.")).toBe("Sets the cap.");
    expect(firstSentence("Is it on? Yes.")).toBe("Is it on?");
  });

  it("does not end on an abbreviation", () => {
    const text = "Model name used for the analyst calls when llm.provider is openai, e.g. gpt-4o-mini or a local name. More.";
    expect(firstSentence(text)).toBe("Model name used for the analyst calls when llm.provider is openai, e.g. gpt-4o-mini or a local name.");
    expect(firstSentence("Names one, i.e. the first. Next.")).toBe("Names one, i.e. the first.");
  });

  it("returns text without a sentence end whole", () => {
    expect(firstSentence("no stop here")).toBe("no stop here");
    expect(firstSentence("ends with e.g.")).toBe("ends with e.g.");
  });
});
