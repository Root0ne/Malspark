// @vitest-environment jsdom
/**
 * DialogPanel: a modal that fits the window.
 *
 * The panel is capped at the dynamic viewport height, its body is the only
 * region that scrolls, and the action row is a sibling of that body rather
 * than inside it.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import DialogPanel from "@/components/ui/DialogPanel";

function render(withFooter: boolean): Document {
  const out = renderToStaticMarkup(
    createElement(
      DialogPanel,
      {
        titleId: "t",
        title: "Analyze a.exe",
        onClose: () => {},
        footer: withFooter ? createElement("button", null, "Start analysis") : undefined,
      },
      createElement("p", null, "body text"),
    ),
  );
  return new DOMParser().parseFromString(out, "text/html");
}

describe("DialogPanel", () => {
  it("caps the panel at the viewport height as a flex column", () => {
    const panel = render(true).querySelector<HTMLElement>("[data-dialog-panel]")!;
    expect(panel.getAttribute("role")).toBe("dialog");
    expect(panel.className).toContain("max-h-[calc(100dvh-2rem)]");
    expect(panel.className).toContain("flex-col");
  });

  it("scrolls only the body, which may shrink below its content", () => {
    const body = render(true).querySelector<HTMLElement>("[data-dialog-body]")!;
    expect(body.className).toContain("overflow-y-auto");
    expect(body.className).toContain("min-h-0");
    expect(body.textContent).toBe("body text");
  });

  it("keeps the action row outside the scrolling body", () => {
    const doc = render(true);
    const body = doc.querySelector("[data-dialog-body]")!;
    const footer = doc.querySelector("[data-dialog-footer]")!;
    expect(body.contains(footer)).toBe(false);
    expect(footer.parentElement).toBe(body.parentElement);
    expect(footer.className).toContain("shrink-0");
    expect(footer.textContent).toBe("Start analysis");
  });

  it("draws no action row without a footer", () => {
    expect(render(false).querySelector("[data-dialog-footer]")).toBeNull();
  });
});
