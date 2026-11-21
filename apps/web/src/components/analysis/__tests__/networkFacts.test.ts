import { describe, expect, it } from "vitest";

import type { MalwareReport, NetworkDomain, NetworkIOCs, NetworkIP } from "@/types/malware-report";
import { domainFacts, endpointCounts, formValues, ipFacts, networkCounts } from "../networkFacts";
import { hostLabel, hostRows, hostSuspicious } from "../networkView";

function ip(over: Partial<NetworkIP> = {}): NetworkIP {
  return {
    address: "203.0.113.7",
    port: 443,
    transport: "tcp",
    asn: null,
    geo: null,
    is_suspicious: false,
    reputation: null,
    ...over,
  };
}

function domain(over: Partial<NetworkDomain> = {}): NetworkDomain {
  return {
    fqdn: "c2.example",
    queried_pids: [],
    resolved_ips: [],
    is_suspicious: false,
    reason: null,
    dga_score: null,
    is_punycode: false,
    homograph_target: null,
    source: "sandbox",
    reputation: null,
    ...over,
  };
}

describe("what an address row says about who reached it", () => {
  it("says nothing the row does not carry: an unset tree flag is not a no", () => {
    expect(ipFacts(ip())).toEqual([]);
    expect(ipFacts(ip({ sample_process_tree: null }))).toEqual([]);
  });

  it("says the sample's tree reached it, or names the processes that did instead", () => {
    expect(ipFacts(ip({ sample_process_tree: true }))).toEqual([
      "The sandbox saw the sample's own process tree reach this address.",
    ]);
    expect(
      ipFacts(ip({ sample_process_tree: false, outside_processes: ["svchost.exe (procid 4)"] })),
    ).toEqual([
      "Every flow the sandbox attributes came from outside the sample's tree: svchost.exe (procid 4).",
    ]);
  });

  it("names the processes the two lineage facts disagree about, and a public resolver", () => {
    expect(
      ipFacts(
        ip({
          marked_only_processes: ["a.exe (procid 9)"],
          marked_by: "Sandbox A",
          file_only_processes: ["b.exe (procid 10)"],
          public_resolver: true,
        }),
      ),
    ).toEqual([
      "Named the sample's only by Sandbox A's own mark: a.exe (procid 9).",
      "Named the sample's only by the submitted file's process tree: b.exe (procid 10).",
      "A public DNS resolver, which a sandbox guest reaches whatever the sample does.",
    ]);
  });

  it("says who kept the value and who only mentioned it", () => {
    expect(ipFacts(ip({ kept_by: ["network"], mentioned_by: ["static", "judge"] }))).toEqual([
      "Kept as an indicator by network.",
      "Mentioned without being kept by static, judge.",
    ]);
  });
});

describe("what a domain row says", () => {
  it("says a name only the capture's TLS names recorded", () => {
    expect(domainFacts(domain({ capture_only: true }))[0]).toMatch(/only in the capture's TLS names/);
    expect(domainFacts(domain())).toEqual([]);
  });
});

describe("a row of the sample's strings the API serves as its form (T-778)", () => {
  // The IOC table serves a strings row nothing in the run reads as its kind
  // under its form: `dotted_name`, `name_at_domain_text`, ... never `domain`.
  const report = {
    consolidated_iocs: [
      { type: "Dotted name", kind: "dotted_name", value: "Abi.Name", source: "strings" },
      { type: "Name@domain text", kind: "name_at_domain_text", value: "aes128-gcm@openssh.com", source: "strings" },
      { type: "Domain", kind: "domain", value: "c2.example", source: "sandbox" },
    ],
    network: {
      domains: [
        domain({ fqdn: "abi.name", source: "strings", is_suspicious: true, reason: "DGA-like (score 0.82)" }),
        domain({ fqdn: "c2.example", is_suspicious: true, reason: "DGA-like (score 0.71)" }),
      ],
      ips: [],
      urls: [],
    },
    static: {
      interesting_strings: [
        { kind: "domain", value: "abi.name", notes: null },
        { kind: "domain", value: "seen.example", notes: null },
      ],
    },
  } as unknown as MalwareReport;

  it("reads each form row's value with the form it is served as", () => {
    expect([...formValues(report)]).toEqual([
      ["abi.name", "Dotted name"],
      ["aes128-gcm@openssh.com", "Name@domain text"],
    ]);
    expect(formValues(null).size).toBe(0);
  });

  it("counts no form row as a domain and none as suspicious", () => {
    expect(networkCounts(report)).toEqual({ domains: 2, ips: 0, urls: 0, suspicious: 1 });
  });

  it("labels a host the table serves as its form by that form, and never flags it", () => {
    const rows = hostRows(report.network as unknown as NetworkIOCs, formValues(report));
    expect(rows.map((r) => [r.host, hostLabel(r), hostSuspicious(r)])).toEqual([
      ["abi.name", "Dotted name", false],
      ["c2.example", "Domain", true],
    ]);
    const plain = hostRows(report.network as unknown as NetworkIOCs);
    expect(plain.map((r) => [hostLabel(r), hostSuspicious(r)])).toEqual([
      ["Domain", true],
      ["Domain", true],
    ]);
  });

  it("counts every domain as before where the table serves no form row", () => {
    const plain = { ...report, consolidated_iocs: [] } as unknown as MalwareReport;
    expect(networkCounts(plain)).toEqual({ domains: 3, ips: 0, urls: 0, suspicious: 2 });
    expect(endpointCounts(report.network, report.static?.interesting_strings)).toEqual({
      domains: 3,
      ips: 0,
      urls: 0,
    });
  });
});
