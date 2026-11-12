/**
 * The run record's line about correction turns. A report that does not carry
 * the validation block (stored before it existed, or written without it) says
 * so; it is not read as "no producer needed a correction turn", a zero nobody
 * counted. The count is every turn that told a producer what to fix in its
 * answer, whether the answer had the wrong shape or the wrong content; the
 * summary does not keep the two apart.
 */
export function correctionLine(
  validation: { retries?: number | null } | null | undefined,
  countLabel: (n: number, noun: string) => string,
): string {
  if (!validation || typeof validation.retries !== "number") {
    return "This report does not record correction turns.";
  }
  return validation.retries > 0
    ? `${countLabel(validation.retries, "correction turn")} ${
        validation.retries === 1 ? "was" : "were"
      } spent on producers whose answers had to be corrected, in shape or in content.`
    : "No producer needed a correction turn.";
}
