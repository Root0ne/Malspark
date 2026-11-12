<p align="center">
  <img src="apps/docs/public/assets/logo.svg" alt="Malspark" width="112">
</p>

<h1 align="center">Malspark</h1>
<p align="center"><em>Your own malware analysis team</em></p>
<p align="center"><a href="https://malspark.com">malspark.com</a> · <a href="https://malspark.com/docs/">Documentation</a></p>

[![CI](https://github.com/Root0ne/Malspark/actions/workflows/ci.yml/badge.svg)](https://github.com/Root0ne/Malspark/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Root0ne/Malspark/actions/workflows/codeql.yml/badge.svg)](https://github.com/Root0ne/Malspark/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Root0ne/Malspark/badge)](https://scorecard.dev/viewer/?uri=github.com/Root0ne/Malspark)
[![Python](https://img.shields.io/badge/python-3.13-blue)](https://www.python.org/)
[![Licence](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

Malspark is an open-source, self-hosted platform for malware analysis. You
upload a sample, and a team of AI agents analyses it with real tools such as a
decompiler, a disassembler and a sandbox, argues over what it found, and a
judge decides the verdict. Every claim in the report cites the tool call that
proves it, so each one can be checked.

<p align="center">
  <img src="docs/assets/readme/analysis-overview.webp" alt="The Overview tab of a finished analysis in the Malspark console: the verdict, severity, key findings and recommended actions for a Latrodectus sample" width="900">
</p>

## How it works

From upload to report, with no human in the loop:

1. **Code establishes the facts first.** A deterministic triage pack
   identifies the file, hashes it, checks its signature, runs the rule engines
   and decodes its strings.
2. **Analyst agents investigate with real tools:** a decompiler, a
   disassembler, a sandbox, capture readers, reputation services. Each agent
   decides what to call and when to stop.
3. **The analysts argue.** A mediator lists every contradiction between their
   claims, and the analysts it names revise with the evidence in front of them.
4. **A judge decides** the verdict, the family and the ATT&CK techniques, and
   drops what the evidence does not support.
5. **Every claim cites the evidence.** Each tool call is written to an evidence
   ledger with an id such as `ev_0021`, and every report section names the ids
   it rests on. The ledger is sealed when the run is stored.

The output is a report against MITRE ATT&CK (Markdown, HTML, PDF), a STIX 2.1
bundle, an IOC feed and detection drafts.

The organising rule is that **the agent decides and the code says what is wrong
with the decision.** Nothing rewrites a claim, a technique id or a confidence
behind an agent's back: a problem goes back to the agent with one turn to fix
it, and what it does not fix stays on the record.

Teams, tools, models and sandboxes are configuration. Any MCP server can give
the agents its tools, and a tool Malspark has never seen is used at full
strength. Nothing is bound to Windows: the sample's own bytes decide its route.

## Benchmark

The benchmark run of 2026-11-06: Claude Haiku 5.5 with the all-tools team on a
Latrodectus sample, with a real sandbox, scored against eight public human
analyses of the family.

| Reference facts recovered | Wrong | Verified facts beyond the key | Cost |
| :-- | :-- | :-- | :-- |
| **84 of 89** (56 found, 28 partly) | **0** | **37** | **8.24 USD** (129 model calls, 84 minutes) |

The method and the per-group scores are on the
[benchmark page](https://malspark.com/docs/benchmark/).

## The console

The web console shows each analysis in six tabs, from the Overview to the
Evidence, which holds every tool call, the analysts' discussion and the
debate. Teams and tool servers are configured in its settings.

<table>
  <tr>
    <td width="50%" valign="top">
      <img src="docs/assets/readme/evidence-debate.webp" alt="Evidence, Debate view: how the debate ended, the mean claim confidence by round, and each round's blocking and non-blocking lines with the mediator's reading">
      <p><b>Debate.</b> How the debate ended, and each round's blocking and
      non-blocking lines with the mediator's reading.</p>
    </td>
    <td width="50%" valign="top">
      <img src="docs/assets/readme/evidence-analyst-discussion.webp" alt="Evidence, Analyst discussion view: the participating agents with their tool counts, and the triage pack's tool calls, each with its evidence id">
      <p><b>Analyst discussion.</b> The participants, what each said and the
      tool calls they made, each call linked to its row in the evidence
      records.</p>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <img src="docs/assets/readme/settings-teams.webp" alt="Settings, Teams: a team's ordered stages being edited, with the stage graph drawn beside them">
      <p><b>Teams.</b> The team editor draws each team's stage graph and
      checks the team as it is edited.</p>
    </td>
    <td width="50%" valign="top">
      <img src="docs/assets/readme/settings-tool-servers.webp" alt="Settings, Tool servers (MCP): the list of configured servers and one server's transport, URL, auth token and the agents allowed its tools">
      <p><b>Tool servers.</b> Each MCP server's transport and connection, and
      the agents that may call its tools.</p>
    </td>
  </tr>
</table>

The [Console](https://malspark.com/docs/console/) page describes every view.

## The teams that ship

| Team | Stages | For |
| :-- | :-- | :-- |
| `default` | `triage_pack` → `analysis` (static, dynamic, network) → `debate` → `verdict` → `report` | The general case: three analysts, with the pack in front of them. |
| `measurement` | The same four model stages, without the pack and with every tool server withheld | What the agents contribute on their own, with nothing to call. |
| `mobile` | `triage_pack` → `triage` → `android_static` → `dynamic` → `debate` → `verdict` → `report` | An APK or a DEX. The Android stage declines on anything else and says so. |
| `deep_static` | `triage_pack` → `triage` → `static` → `reversing` → `network` → `debate` → `verdict` → `report` | Reading the code: the reversing stage takes each static finding into the decompiler. |
| `team_lead` | `triage_pack` → `lead` → `verdict` → `report` | One lead agent plans, asks the specialists through `ask_<agent>` tools, and reports what they established. |

`triage_pack` is the deterministic pre-analysis pack, which runs no model; the
`triage` stage after it is the triage *agent*. A team of your own is written in
the console; the benchmark's all-tools team is
[an importable example](docs/examples/profiles/all-tools.json).

## Quick start

The compose stack is the supported way to run Malspark. It needs Docker with
the Compose plugin and [uv](https://astral.sh/uv/), on Windows (PowerShell),
macOS or Linux; the setup commands use the standard library only.

**Supported systems:** Windows (native PowerShell with Docker Desktop), macOS
and Linux. CI installs a fresh checkout on Ubuntu, macOS and Windows runners
and runs the host-side unit suites on Windows, as checks that do not gate a
merge.

```bash
git clone https://github.com/Root0ne/Malspark.git && cd Malspark
uv run --no-project python scripts/dev/malspark_dev.py setup     # third-party trees and rule corpora
uv run --no-project python scripts/dev/malspark_dev.py env init  # docker/.env and bootstrap.env, secrets generated
uv run --no-project python scripts/dev/malspark_dev.py doctor    # what the host still lacks
uv run --no-project python scripts/dev/malspark_dev.py up        # docker compose up -d, development overlay
```

With make, the same commands are `make external`, `make env-init`, `make doctor`
and `make dev-up`; `make setup` also installs the development dependencies and
pre-commit.

Create the first admin account with `make create-admin EMAIL=you@example.com`,
sign in at <http://localhost:3000>, then walk **Settings → Setup guides** to connect
a language model, a sandbox and the tools. The
[quick start](https://malspark.com/docs/getting-started/) has every command,
and [Deployment](https://malspark.com/docs/deployment/) covers production.

<p align="center">
  <img src="apps/docs/public/assets/architecture.svg" alt="Malspark runtime components" width="720">
</p>

## Releases

Each release publishes the container images to the GitHub Container Registry
as `ghcr.io/root0ne/malspark-<name>` (`backend`, `frontend`, `minio` and the
tool sidecars), tagged `<version>` and `<major>.<minor>`, and attaches the
wheel, the sdist and `SHA256SUMS` to the
[GitHub release](https://github.com/Root0ne/Malspark/releases). The images,
the wheel and the sdist are signed with cosign keyless and carry a build
provenance attestation. [RELEASING.md](RELEASING.md) lists every image and the
commands that verify them.

## Documentation

The full documentation is at <https://malspark.com/docs/>. The pages live in
[apps/docs/content/docs/](apps/docs/content/docs/).

| Section | Pages |
| :-- | :-- |
| Introduction | [Overview](https://malspark.com/docs/), [Quick start](https://malspark.com/docs/getting-started/) |
| Concepts | [Pipeline](https://malspark.com/docs/concepts/pipeline/), [Agents and teams](https://malspark.com/docs/usage/teams/), [Evidence ledger](https://malspark.com/docs/concepts/ledger/), [Debate and judge](https://malspark.com/docs/concepts/debate-and-judge/), [Report](https://malspark.com/docs/concepts/report/), [Validation and feedback](https://malspark.com/docs/concepts/validation/) |
| Guides | [Running an analysis](https://malspark.com/docs/usage/running-an-analysis/), [Console](https://malspark.com/docs/console/), [Reports and exports](https://malspark.com/docs/usage/reports-and-exports/), [CI](https://malspark.com/docs/integrations/ci/) |
| Bring your own tools | [Overview](https://malspark.com/docs/tools/), [MCP servers](https://malspark.com/docs/integrations/mcp-servers/), [Sidecars](https://malspark.com/docs/tools/sidecars/), [Generic MCP servers](https://malspark.com/docs/tools/generic-mcp/) and the built-in tools |
| Models and sandboxes | [LLM providers](https://malspark.com/docs/providers/), [Sandboxes](https://malspark.com/docs/tools/sandboxes/) |
| Reference | [Configuration](https://malspark.com/docs/configuration/), [REST API](https://malspark.com/docs/api/), [CLI](https://malspark.com/docs/cli/), [Validation codes](https://malspark.com/docs/validation-codes/), [Security](https://malspark.com/docs/security/), [Architecture](https://malspark.com/docs/architecture/) |
| Operations | [Deployment](https://malspark.com/docs/deployment/), [Upgrades](https://malspark.com/docs/upgrades/), [Backups](https://malspark.com/docs/backups/), [Monitoring](https://malspark.com/docs/monitoring/), [Day-to-day operations](https://malspark.com/docs/operations/) |
| Development | [Development](https://malspark.com/docs/development/) |
| Benchmark | [The benchmark run](https://malspark.com/docs/benchmark/) |

Release notes are in [CHANGELOG.md](CHANGELOG.md).

## Contributing

Discuss a substantial change in an issue first. Branch from `dev` and open the
pull request against `dev`; [CONTRIBUTING.md](CONTRIBUTING.md) has the workflow
and the gates to run locally. Everyone taking part follows the
[code of conduct](CODE_OF_CONDUCT.md).

## Security

Report a vulnerability through
[private vulnerability reporting](https://github.com/Root0ne/Malspark/security/advisories/new),
never a public issue. [SECURITY.md](SECURITY.md) says what to include and what
to expect.

## Support

Bug reports and feature requests go to
[GitHub issues](https://github.com/Root0ne/Malspark/issues), through their
forms. Setup, configuration and operations are covered in the
[documentation](https://malspark.com/docs/).

## Licence

MIT — see [LICENSE](LICENSE). The third-party rule sets Malspark can use carry
their own licences and are not redistributed here; `make external` fetches
them, licence files included.
