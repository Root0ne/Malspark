### Fixed

- **A capture's conversation names both ends of the flow and what each sent.** Every line of
  the capture summary (the `pcap_summary` tool's text, the network sidecar's, the network
  analyst's pack, the triage pack and the report's "Capture summary") gives the totals and
  then each direction, as `<internal> → <peer> K pkts, B bytes` and the way back, a direction
  that carried nothing written `none`. It gave only the peer's share and called it "from the
  host", which read as the sandbox's own machine and turned a download into an upload. The
  internal end is the address the capture gives that is not public, by the summary's own
  rule; a conversation with no internal end says so and names the public sender. The
  record's keys say what they hold: `internal`, `packets_to_peer`/`bytes_to_peer`,
  `packets_from_peer`/`bytes_from_peer`, and `public_senders` with
  `packets_public_to_peer`/`bytes_public_to_peer` when a public address sent to the peer. A
  record stored with the old keys is printed with the peer's share as the peer's and says it
  does not name the internal end; one that counted only the packets toward the peer says it
  does not state what the peer sent. No count changes.
