/**
 * The Network tab's hosts and the requests each one received.
 *
 * Every name and address the run saw is one host: a domain the sample
 * resolved and an address it reached are listed together, so a reader picks a
 * host first and then reads what was asked of it. A request belongs to the
 * host its URL names, compared without case; a URL whose host is an address
 * belongs to that address. A request whose URL names no host the list holds
 * still has its own row in the requests table, so nothing is reachable only
 * through a host.
 */

import type { NetworkDomain, NetworkIOCs, NetworkIP, NetworkURL } from "@/types/malware-report";
import { valueKey } from "./networkFacts";

/** How many rows each network table draws before offering more. */
export const NETWORK_ROWS_STEP = 10;

export type HostRow =
  | {
      kind: "domain";
      key: string;
      host: string;
      domain: NetworkDomain;
      requests: NetworkURL[];
      /** The form the IOC table serves the value as (`networkFacts.formValues`), or "". */
      form: string;
    }
  | { kind: "ip"; key: string; host: string; ip: NetworkIP; requests: NetworkURL[] };

/** The host a URL names, lower-cased, or "" when it names none. */
export function urlHost(url: string | null | undefined): string {
  const text = String(url ?? "").trim();
  if (!text) return "";
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `http://${text}`;
    return new URL(withScheme).hostname.replace(/^\[|\]$/g, "").toLowerCase();
  } catch {
    const m = /^(?:[a-z][a-z0-9+.-]*:\/\/)?([^/:?#\s]+)/i.exec(text);
    return m ? m[1].toLowerCase() : "";
  }
}

/**
 * Every host the network block names, domains first, each with its requests.
 * A name the IOC table serves as its form (`forms`, keyed by `valueKey`) keeps
 * its row and carries that form.
 */
export function hostRows(
  net: NetworkIOCs | null | undefined,
  forms: ReadonlyMap<string, string> = new Map(),
): HostRow[] {
  if (!net) return [];
  const urls = net.urls ?? [];
  const requestsOf = (host: string) => {
    const wanted = host.trim().toLowerCase();
    return wanted ? urls.filter((u) => urlHost(u.url) === wanted) : [];
  };
  const rows: HostRow[] = [];
  (net.domains ?? []).forEach((domain, i) =>
    rows.push({
      kind: "domain",
      key: `d${i}`,
      host: domain.fqdn,
      domain,
      requests: requestsOf(domain.fqdn),
      form: forms.get(valueKey(domain.fqdn)) ?? "",
    }),
  );
  (net.ips ?? []).forEach((ip, i) =>
    rows.push({ kind: "ip", key: `i${i}`, host: ip.address, ip, requests: requestsOf(ip.address) }),
  );
  return rows;
}

/** Whether a host is flagged suspicious by the run; a name served as its form is no host to flag. */
export function hostSuspicious(row: HostRow): boolean {
  return Boolean(row.kind === "domain" ? !row.form && row.domain.is_suspicious : row.ip.is_suspicious);
}

/** What a host row is: a domain, an address, or the form the IOC table serves the name as. */
export function hostLabel(row: HostRow): string {
  if (row.kind === "ip") return "IP address";
  return row.form || "Domain";
}

/**
 * Why the network block flags a domain and its generated-name score, as the
 * host detail says them: nothing on a name the IOC table serves as its form,
 * since both read it as a host. A score of 0 is not said.
 */
export function hostReading(row: HostRow): { reason: string; score: number | null } {
  if (row.kind !== "domain" || row.form) return { reason: "", score: null };
  const score = row.domain.dga_score;
  return {
    reason: row.domain.reason ?? "",
    score: typeof score === "number" && score > 0 ? score : null,
  };
}

/** The enrichment record of a host, when the run holds one. */
export function hostReputation(row: HostRow): Record<string, unknown> | null {
  const rep = row.kind === "domain" ? row.domain.reputation : row.ip.reputation;
  return rep && typeof rep === "object" ? (rep as Record<string, unknown>) : null;
}

/** Where a host came from: the sandbox, an analyst, or the sample's strings. */
export function hostSource(row: HostRow): string | null {
  return (row.kind === "domain" ? row.domain.source : row.ip.source) ?? null;
}

/** What a reader needs to know about a source word. */
export function sourceExplanation(source: string): string {
  if (source === "strings") return "Found in the sample's bytes, not observed on the wire";
  if (source === "sandbox") return "Resolved or requested by the sample under the sandbox";
  return "Recorded by an analyst";
}
