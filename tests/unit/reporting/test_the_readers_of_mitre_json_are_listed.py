"""Every file that reads, writes, serves or names mitre.json's rows is listed with what it does.

mitre.json's ``description`` is the text the analyst report's ATT&CK table prints for each
technique (T-727): an export, read by no prompt, tool answer, check or decision. A new
reader of the stored ``mitre_techniques`` column or of the ``/mitre`` answer fails this test
until it is listed here with its use, so a model input built from the field is a decision
made in review, never one made in passing. The platform's own package (where every prompt is
built) only names the answer in its prose.
"""

from __future__ import annotations

import io
import re
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCANNED = ("apps/api/app", "src/malspark", "scripts", "apps/web/src")
SUFFIXES = (".py", ".ts", ".tsx")
PATTERN = re.compile(
    r"\bmitre_techniques\b|get_mitre_techniques|/mitre[\"'`]|mitre\.json[\"'`]|-mitre\.json"
)

READERS = {
    # The API: the column, its writers, what serves and what copies it.
    "apps/api/app/models/report.py": "the stored column",
    "apps/api/app/schemas/job.py": "the column in the job detail's report row",
    "apps/api/app/worker/analysis_worker.py": "writes the column at the store",
    "apps/api/app/worker/enrich_worker.py": "writes the column again at an enrichment write",
    "apps/api/app/services/report_service.py": "/mitre (descriptions from the served report); "
    "the report list counts the rows",
    "apps/api/app/api/v1/reports.py": "the /mitre route",
    "apps/api/app/services/ledger_chain.py": "digests the column",
    "apps/api/app/services/run_export.py": "copies the stored column into the run export",
    # The console: ids, names and tactics, and the download of /mitre whole.
    "apps/web/src/lib/api.ts": "fetches /mitre; the report row's type",
    "apps/web/src/components/ui/exportActions.ts": "downloads /mitre whole",
    "apps/web/src/components/analysis/tabs/AttackContent.tsx": "a fallback technique list",
    "apps/web/src/components/analysis/capabilityHeatmap.ts": "ids, names, tactics, layers",
    "apps/web/src/components/analysis/analysisTabs.ts": "whether a report maps techniques",
    "apps/web/src/components/analysis/analysisMap.ts": "where the field is drawn",
    "apps/web/src/app/(app)/analysis/[id]/behaviour/page.tsx": "technique tactics",
    # Scripts: scoring, publishing, auditing and replaying the stored runs.
    "scripts/benchmark/provenance.py": "collects the evidence ids of each row",
    "scripts/benchmark/publish_evidence.py": "copies a run's mitre.json",
    "scripts/audit/surfaces.py": "technique id to name",
    "scripts/replay/render_surfaces.py": "renders and compares /mitre",
    # The platform's package: named in prose only (no code token reads it).
    "src/malspark/extractors/capability_matrix.py": "named in prose",
    "src/malspark/memory/long_term_memory.py": "named in prose",
    "src/malspark/reporting/models.py": "named in prose",
    "src/malspark/reporting/renderers/markdown.py": "named in prose",
    "src/malspark/reporting/renderers/stix_renderer.py": "named in prose",
}


def _found() -> set[str]:
    found: set[str] = set()
    for top in SCANNED:
        for path in (ROOT / top).rglob("*"):
            if path.suffix not in SUFFIXES or "__tests__" in path.parts or ".test." in path.name:
                continue
            if PATTERN.search(path.read_text(encoding="utf-8")):
                found.add(path.relative_to(ROOT).as_posix())
    return found


def test_every_reader_of_mitre_json_is_listed_with_its_use() -> None:
    assert _found() == set(READERS)


def test_the_platform_package_names_mitre_json_only_in_its_prose() -> None:
    for name in (n for n in READERS if n.startswith("src/malspark/")):
        source = (ROOT / name).read_text(encoding="utf-8")
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.NAME:
                assert token.string not in ("mitre_techniques", "get_mitre_techniques"), name
