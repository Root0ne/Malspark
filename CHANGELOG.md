# Changelog

Notable changes to Malspark. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); dates are the day a
change landed on `main`.

## Unreleased

## [1.0.0] - 2026-11-08

The first public release of Malspark: AI agents analyse a malware sample from
start to finish, and every claim in the report cites the tool call that proves
it.

### Added

#### Analysis

- **Autonomous multi-agent analysis.** A team of agents analyses a sample with
  no human in the loop; each agent decides which tools to call, in what order
  and when to stop.
- **Agents and teams are configuration.** An agent is a model, a prompt, a
  role and a set of tools; a team is an ordered list of stages, each running
  every agent it names, with an optional condition. Teams are written in the
  console and exported or imported as JSON.
- **Five teams ship:** `default`, `mobile`, `deep_static`, `team_lead` and
  `measurement`, built from nine agent definitions, plus an importable
  all-tools team.
- **Delegation.** An agent can hand a task to another through an
  `ask_<agent>` tool, so a lead agent can plan an analysis and ask the
  specialists.
- **Format-agnostic routing.** The sample's own bytes decide its route: PE,
  ELF, Mach-O, APK, DEX, documents, scripts and archives. A format nothing
  recognises still gets an analysis, and the report says so.
- **The triage pack.** Before any agent starts, code runs a fixed list of
  tools — identity, hashes, signature, structure, strings, YARA, capa, FLOSS,
  the sandbox record, reputation — with no model. Its steps are data, and a
  step can call any tool server's tool.
- **Debate, mediator and judge.** A mediator lists every contradiction still
  standing and names the analysts who must revise; the judge states the
  verdict, the family and the ATT&CK techniques, and drops what the evidence
  does not support.
- **Validation codes.** When a claim breaks a rule the code tells the agent
  why and gives it a turn to fix it; nothing rewrites a claim behind an
  agent's back. Every code is listed on a page generated from the source.
- **Long-term memory.** Cases, similar samples and function-hash families are
  kept in Qdrant; a job can ignore other runs of its sample or keep a memory
  of its own.

#### Evidence

- **The evidence ledger.** Every tool call is an entry with an `ev_` id, its
  arguments and its whole answer, and is sealed with a digest and an HMAC
  chain when the run is stored.
- **Claims cite the ledger.** A claim that cites no entry, or an entry that
  does not hold what the claim says, is flagged, and every report section
  names the entries it rests on.
- **Job package.** One signed file carries a job's evidence and can be
  verified on its own.

#### Tools and sandboxes

- **Tools plug in with no code change:** any MCP server over stdio or HTTP,
  shipped sidecars, static providers, sandboxes, and provider plugins
  installed as packages.
- **Undeclared tools at full strength.** A server Malspark has never seen gets
  every tool it advertises, its own descriptions uncut and no call limits; a
  declaration only lets the platform read its answers as facts.
- **Sidecars:** Detect It Easy, ILSpy, GoReSym, YARA-X, oletools, webcrack,
  unblob and JADX, and the platform's own analysis and network servers, each
  in a container of its own.
- **Static providers:** Ghidra, radare2, capa and YARA, or any MCP server.
- **Sandboxes:** CAPEv2, Hatching Triage, any REST sandbox, a sandbox served
  over MCP, and an uploaded report, all read into one neutral report; the
  mock sandbox, the default, executes nothing.
- **VirusTotal** through VirusTotal's own MCP server, switched off until an
  operator registers an agent token.

#### Reports

- **The analyst report** as Markdown, HTML and PDF, with an executive summary,
  the execution flow, configuration, commands and C2 channels, each section
  citing the ledger.
- **ATT&CK:** every technique is checked against the vendored catalogue and
  the sample's platform before it is published, and an ATT&CK Navigator layer
  is exported.
- **STIX 2.1 bundle and IOC feed,** with a publish decision on every indicator
  row; one publish rule decides what the bundle, the table and the feed carry.
- **Detection drafts** for YARA, Sigma and Suricata, matching only what
  the run publishes.
- **The evidence bundle** beside the report, and a section-by-section
  comparison of two runs.
- **What left this machine:** the report states where the sample was read and
  what each tool did beyond answering, and marks an undeclared tool as such.
- **Enrichment:** threat-intelligence lookups for a report's indicators run as
  a job of their own and never delay a verdict.

#### Console

- **A live view of every run:** the agents' conversation as it happens, the
  evidence, the relationship graph of the STIX bundle, and run comparison.
- **Settings in the console:** every setting is editable in exactly one group,
  with setup guides for a model, a static analyser, a sandbox and a team, and
  a team editor that checks each team as it is typed.

#### Models

- **LLM providers:** OpenAI-compatible endpoints (OpenAI's API, DeepSeek, a
  local llama.cpp server), Anthropic, Gemini and Ollama.
- **Per-agent models:** each agent can have its own provider, model,
  temperature, effort and endpoint, with fallback models; a model is probed
  before a job may name it.
- **Spend ceiling:** an optional per-job ceiling priced from configured model
  prices.

#### Security

- **Authentication and roles:** JWT sessions with single-use refresh tokens
  and replay detection, hashed API keys, and `admin` and `analyst` roles.
- **Secrets encrypted at rest** under a settings key; no tool server's
  environment carries the platform's own secrets.
- **Isolated tool servers:** the containers that open the sample run
  unprivileged, with no Linux capability, on internal networks with no route
  to the platform's stores.
- **A private object store:** the bucket is checked for anonymous access, and
  samples and reports are not stored or served while it is readable by
  anyone.
- **Audit chain:** security-relevant actions are written to a keyed,
  chained audit log, whose head can be anchored outside the database.
- **Rate limits and login protection** on the API.

#### Verification

- **Replay** re-runs the platform's rules over a stored run's recorded
  answers, and compares two code revisions over the same runs.
- **The known-answer gate** scores runs against a reference key and fails a
  change that drops a credited item; blind A/B scoring and a calibration set
  sit beside it.
- **Rehearsal** proves a configuration offline against a stub model before
  any paid run.

#### Deployment

- **A Compose stack** with the API, workers, console, PostgreSQL, Redis,
  MinIO, Qdrant and optional sidecar profiles; the CLI runs an analysis
  outside it.
- **Native amd64 and arm64 images:** the release publishes every image for
  both but Detect It Easy's, which is amd64 only. On an Apple Silicon Mac, the
  locally built Ghidra image and Detect It Easy run emulated under Rosetta.
- **Signed and attested releases:** every image and Python artefact is signed
  with cosign keyless and carries SLSA build provenance.
- **macOS:** the stack runs on an Apple Silicon Mac, and the tests, API and
  worker run natively on macOS.
