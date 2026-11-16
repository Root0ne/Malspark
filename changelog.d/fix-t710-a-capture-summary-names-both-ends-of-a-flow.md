### Fixed

- **A capture's conversation names both ends of the flow and what each sent.** Every line of
  the capture summary (the `pcap_summary` tool's text, the network sidecar's, the network
  analyst's pack, the triage pack and the report's "Capture summary") gives the totals and
  then what each end sent, as `<internal> sent K pkts, B bytes; <peer> sent K pkts, B bytes`,
  an end that sent nothing written `none`. Each direction names only the addresses that sent
  in it: the peer's names the internal ends it sent to wherever they are not exactly the ones
  that sent to it, an internal end that only received is never named as a sender, and a
  public address that sent to the peer is named with what it sent. The internal end is an
  address the capture gives that is not public, by the summary's own rule; a conversation
  with no internal end says so. The record's keys say what they hold: `internal`,
  `packets_to_peer`/`bytes_to_peer`, `packets_from_peer`/`bytes_from_peer`,
  `internal_to_peer`/`internal_from_peer` when the two directions have different internal
  ends, and `public_senders` with `packets_public_to_peer`/`bytes_public_to_peer`. A record
  stored with the old keys is printed with the peer's share as the peer's, says the other end
  is not recorded, and keeps every other line its writer stored. The report's "Capture summary"
  has a room 3.3 times a text section's, so every capture the shorter line fitted whole fits
  whole; past it, conversations are left out first, the heaviest kept, then TLS names, each
  with how many are left out and where they all are, and the overview and beacons are printed
  whole. The triage
  pack parts the conversations with ` | `. No count changes.
