/**
 * What a reputation service said about this sample, as the report recorded it.
 *
 * Any server whose tool declares `kind: reputation` is a reputation source.
 * Its answer is read once, through the paths its declaration gives, when the
 * entry is written, and the report carries every such record in `reputation`
 * (`malspark.core.reputation`): the service's declared name, the engine counts,
 * the labels, the dates, the link and the service's own words. This module
 * reads only that record — no tool name, no service's answer shape — so a
 * reputation server an operator adds draws the same section as the built-ins.
 *
 * A report stored before the records has no `reputation` field at all; its
 * section is read by the legacy reader (`reputationLegacy.ts`). An empty list
 * is a run whose lookups established nothing, and draws no section.
 */

import type { MalwareReport, ReputationAnswer } from "@/types/malware-report";

export interface Reputation {
  /** The heading: the service that was asked, by its declared name. */
  service: string;
  entryId: string;
  /** Engines that returned a verdict, when the answer counted them. */
  engines: number | null;
  malicious: number | null;
  suspicious: number | null;
  /** The names the service gives this file, in the order it gave them. */
  labels: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  /** Where to read the full report. Absent unless the answer carried one. */
  link: string | null;
  /** The service's own words, kept whenever there are no counts to show. */
  summary: string;
  /**
   * The counts the record holds, each under the record's own name for it
   * (`countsWords`); absent on a section read from a report stored before
   * the records, which draws its figure as it always did.
   */
  counts?: string | null;
}

/** Whether a report carries reputation records, which then are all this reads. */
export function carriesReputationRecords(
  report: Pick<MalwareReport, "reputation"> | null | undefined,
): boolean {
  return Array.isArray(report?.reputation);
}

function count(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

/** The words the counts line uses as labels of its own (`COUNT_LABELS`). */
const COUNT_LABELS = new Set(["malicious", "suspicious", "engines", "total"]);

/**
 * A counts object's member name as the line prints it (`member_name`): as the
 * answer wrote it where it is a plain token that is none of the line's labels,
 * otherwise as a quoted JSON string, the answer's own key.
 */
function memberName(name: string): string {
  return /^[A-Za-z0-9_.-]+$/.test(name) && !COUNT_LABELS.has(name) ? name : JSON.stringify(name);
}

/**
 * The counts a record holds, as the report's header cell prints them
 * (`malspark.core.reputation.counts_line`), or `null` when it holds none.
 *
 * The flagged count (`malicious`) always, or that the record holds none where
 * its counts object holds no member of that name either; then each member of
 * the answer's counts object (`stats`) that is not zero, under
 * the name the answer wrote it under (quoted where it is no plain token or is
 * one of the line's own labels); the engine count the service gave beside
 * them, and the total unless it is the sum of the members. The member of the
 * flagged or the suspicious name is left out only where it equals the record's
 * field of that name (`suspicious` then printed in its place); where the two
 * differ, or the record has no field of that name, the member is printed
 * quoted, also a zero. `suspicious` the object does not hold is printed where
 * it is not zero. Never a fraction and no "of": the counts are named, and no
 * tally is claimed whole.
 *
 * Members come in the order of the parsed `stats` object: the order the API
 * served them, except that a name that is a whole number (`"0"`, `"10"`)
 * comes first, in numeric order, as every JavaScript object orders such keys.
 * A count is drawn as the browser parsed it: a whole number beyond 2^53 is
 * not held exactly and may be drawn with other digits than the record's.
 */
export function countsWords(answer: ReputationAnswer): string | null {
  const stats = Object.entries(answer.stats ?? {}).filter(
    (pair): pair is [string, number] => count(pair[1]) !== null,
  );
  const malicious = count(answer.malicious);
  const suspicious = count(answer.suspicious);
  const members: string[] = [];
  for (const [name, value] of stats) {
    // The record's field of the member's name, where it has one.
    const field = name === "malicious" ? malicious : name === "suspicious" ? suspicious : null;
    if (field !== null && value === field) {
      if (name === "suspicious" && value !== 0) members.push(`suspicious ${value}`);
      continue;
    }
    if (value !== 0 || name === "malicious" || name === "suspicious") {
      members.push(`${memberName(name)} ${value}`);
    }
  }
  const held = stats.find(([name]) => name === "suspicious")?.[1] ?? null;
  if (suspicious !== null && held !== suspicious && (suspicious !== 0 || held !== null)) {
    members.push(`suspicious ${suspicious}`);
  }
  const beside: string[] = [];
  const engines = count(answer.engines);
  if (engines !== null) beside.push(`engines ${engines}`);
  const total = count(answer.total);
  const summed = stats.length > 0 && total === stats.reduce((sum, [, value]) => sum + value, 0);
  if (total !== null && !summed) beside.push(`total ${total}`);
  if (members.length === 0 && beside.length === 0 && malicious === null) return null;
  if (malicious !== null) members.unshift(`malicious ${malicious}`);
  else if (!stats.some(([name]) => name === "malicious")) members.unshift("malicious not counted");
  return [members.join(", "), ...beside].join("; ");
}

/** One recorded answer as a section, or `null` when it established nothing. */
export function reputationFromRecord(
  answer: ReputationAnswer | null | undefined,
): Reputation | null {
  if (!answer || typeof answer !== "object") return null;
  // One denominator, as the report states it: the engines the service counted,
  // else the total of its counts (`ReputationRecord.engine_count`).
  const engines = count(answer.engines) ?? count(answer.total);
  const labels = Array.isArray(answer.labels)
    ? answer.labels.filter((label): label is string => typeof label === "string" && !!label)
    : [];
  const summary = text(answer.summary) ?? "";
  const malicious = count(answer.malicious);
  if (engines === null && malicious === null && labels.length === 0 && !summary) return null;
  const link = text(answer.link);
  return {
    service: text(answer.service) ?? "Reputation",
    entryId: String(answer.entry_id ?? ""),
    engines,
    malicious,
    suspicious: count(answer.suspicious),
    labels,
    firstSeen: text(answer.first_seen),
    lastSeen: text(answer.last_seen),
    link: link && /^https?:\/\//i.test(link) ? link : null,
    summary,
    counts: countsWords(answer),
  };
}

/** The first recorded answer that established something, in ledger order. */
export function reputationFromReport(
  report: Pick<MalwareReport, "reputation"> | null | undefined,
): Reputation | null {
  for (const answer of report?.reputation ?? []) {
    const reputation = reputationFromRecord(answer);
    if (reputation) return reputation;
  }
  return null;
}

/**
 * A network endpoint's enrichment record, as the badge beside the row says it.
 *
 * The badge used to colour the record red, orange or green by thresholds of
 * its own (70 / 30 on a score, 5 / 1 on a count), which disagreed with the
 * thresholds the source declares (`malicious_when`): an AbuseIPDB score of 50
 * that the source calls malicious drew orange, a VirusTotal answer with three
 * `suspicious` engines and no `malicious` one — malicious by its declaration —
 * drew green. The declared verdict is what the enrichment writes into the row
 * itself (`is_suspicious`), so the badge no longer second-guesses it: it names
 * the source and the figure the record carries, under the field's own name,
 * in a neutral tone.
 */
export function endpointReputation(
  record: Record<string, unknown> | null | undefined,
): { source: string; figure: string | null; verdict: boolean | null } | null {
  if (!record || typeof record !== "object") return null;
  const source = text(record.source) ?? "intel";
  const malicious = count(record.malicious);
  const suspicious = count(record.suspicious);
  const abuse = count(record.abuse_confidence);
  const parts: string[] = [];
  if (malicious !== null) parts.push(`malicious ${malicious}`);
  if (suspicious !== null && suspicious > 0) parts.push(`suspicious ${suspicious}`);
  if (abuse !== null) parts.push(`abuse ${abuse}`);
  // The verdict the source's own rule gave the record (`malicious_verdict`):
  // true is malicious by that rule, false is not. A record written before the
  // field, or one the rule could not judge, carries none and the badge draws
  // exactly as it did.
  const verdict = typeof record.malicious_verdict === "boolean" ? record.malicious_verdict : null;
  return { source, figure: parts.length > 0 ? parts.join(" · ") : null, verdict };
}

/**
 * The words the badge adds for a source's declared verdict, with the tone they
 * are drawn in, or `null` when the record carries none.
 *
 * `false` is not "clean": it says every count the source's `malicious_when`
 * rule reads is below its threshold, which is all the source established, so
 * it is worded that way and drawn without a colour.
 */
export function verdictWords(
  verdict: boolean | null | undefined,
): { text: string; tone: "red" | "muted" } | null {
  if (verdict === true) return { text: "malicious by source rule", tone: "red" };
  if (verdict === false) return { text: "below source threshold", tone: "muted" };
  return null;
}

/**
 * The detections figure as the section prints it: the malicious count over
 * the engines, or words saying the count was not given.
 *
 * An answer that counted its engines but not the malicious verdicts among
 * them used to print `0/70` — a clean bill of health the service never gave.
 * The count the answer did not carry is said as missing, not as zero.
 */
export function detectionsFigure(
  reputation: Pick<Reputation, "malicious" | "engines">,
): { count: string; known: boolean } {
  if (reputation.malicious === null) return { count: "not counted", known: false };
  return { count: String(reputation.malicious), known: true };
}

/**
 * What an enrichment record says, as words a tooltip can carry: one line per
 * field that holds a plain value, its name with the underscores read as
 * spaces. A nested value is left to the evidence record it came from.
 */
export function reputationTooltip(rep: Record<string, unknown>): string {
  return Object.entries(rep)
    .filter(([, v]) => typeof v === "string" || typeof v === "number" || typeof v === "boolean")
    .map(([k, v]) => `${k.replace(/_/g, " ")}: ${typeof v === "boolean" ? (v ? "yes" : "no") : String(v)}`)
    .join("\n");
}
