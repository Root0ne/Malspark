"""What a stored definition means when it leaves something out, or kept an old seed.

Two rules, both about reading the definition map a database holds.

A seeded definition is stored whole on every save, so a database holds each
seed's prompt as it was on the day of its last save. A release that rewrites
a seeded prompt must not turn that row into "an operator's own agent on a
reserved name" and rename it out of the way: a prompt the seed itself once
shipped is the seed's.

An operator's definition that has no tool list takes its role seed's list,
and one that has a list, empty included, keeps it: a clone of ``static`` on
r2 written as two fields keeps the analysis sidecar the static seed reads.
"""

from __future__ import annotations

import hashlib

import pytest

from app.services.agent_map import validate_definitions
from malspark.agents import prompts
from malspark.core.config import (
    FORMER_SEED_PROMPT_DIGESTS,
    Settings,
    as_stored_builtin,
    with_the_role_seed_tools,
)

# The reputation paragraph the seeded generic prompts end with, and the one
# they ended with in the release before.
_CURRENT_REPUTATION_PARAGRAPH = """\
When a reputation tool is among your tools: where an entry you were given
already holds a reputation answer for a value, such as the sample's hash, cite
that entry by its evidence id rather than asking again; a lookup adds what no
entry you were given holds, and you cite what comes back with its evidence id
like any other tool result. Weigh a reputation answer as one source: a
reputation label is not the verdict, and an unknown hash is not a clean sample."""
_FORMER_REPUTATION_PARAGRAPH = """\
When a reputation tool is among your tools, look the sample's hash up once and
cite what comes back: a reputation label is one source and not the verdict, and
an unknown hash is not a clean sample."""


def _servers(definition) -> list[str | None]:
    return [ref.server for ref in definition.tools]


class TestAFormerSeedPromptIsTheSeed:
    def _stored_reverser(self, prompt: str) -> dict:
        row = Settings(_env_file=None).agents.definitions["reverser"].model_dump(mode="json")
        row["prompt"] = prompt
        return row

    def test_a_row_saved_under_an_older_seed_loads_as_the_seed(self, monkeypatch) -> None:
        old = "an older seeded prompt"
        digest = hashlib.sha256(old.encode()).hexdigest()
        monkeypatch.setitem(
            FORMER_SEED_PROMPT_DIGESTS,
            "reverser",
            FORMER_SEED_PROMPT_DIGESTS["reverser"] | {digest},
        )

        cfg = Settings(
            _env_file=None, agents={"definitions": {"reverser": self._stored_reverser(old)}}
        )

        assert "reverser_custom" not in cfg.agents.definitions
        assert cfg.agents.definitions["reverser"].prompt == prompts.REVERSER_PROMPT

    def test_the_settings_api_takes_it_as_the_seed_too(self, monkeypatch) -> None:
        old = "an older seeded prompt"
        monkeypatch.setitem(
            FORMER_SEED_PROMPT_DIGESTS,
            "reverser",
            FORMER_SEED_PROMPT_DIGESTS["reverser"] | {hashlib.sha256(old.encode()).hexdigest()},
        )
        stored = validate_definitions(
            {"reverser": self._stored_reverser(old)},
            servers={"analysis": None, "knowledge": None, "virustotal": None},
        )
        assert stored["reverser"]["prompt"] == prompts.REVERSER_PROMPT

    def test_an_operator_s_own_prompt_is_still_moved_out_of_the_way(self) -> None:
        cfg = Settings(
            _env_file=None,
            agents={"definitions": {"reverser": self._stored_reverser("my own reverser")}},
        )
        assert cfg.agents.definitions["reverser_custom"].prompt == "my own reverser"

    @pytest.mark.parametrize(
        ("key", "prompt"),
        [
            ("reverser", prompts.REVERSER_PROMPT),
            ("triage", prompts.TRIAGE_PROMPT),
            ("android_static", prompts.ANDROID_STATIC_PROMPT),
            ("lead", prompts.LEAD_PROMPT),
        ],
    )
    def test_no_current_seed_prompt_is_listed_as_a_former_one(self, key: str, prompt: str) -> None:
        digest = hashlib.sha256(prompt.encode()).hexdigest()
        assert digest not in FORMER_SEED_PROMPT_DIGESTS.get(key, frozenset())

    @pytest.mark.parametrize(
        ("key", "digest"),
        [
            # The reverser prompt before it asked for every branch of a dispatcher.
            ("reverser", "486bffd12746ef38cdd4bcdc94413e03584a5009abb2e4f5bfde6a6d6d3e2875"),
            # The reverser prompt before it was handed resolved hashes and decoded strings.
            ("reverser", "f0add93b08ffd9897fdb84d80f16f8b956681e28c2c3fbce8276f2746c6388b7"),
            # The prompts before a reputation answer the evidence holds was cited by its entry.
            ("reverser", "92a7c46822a62261aa3ece79d887a94190135aaa02e49798ba4d5bc27f0b0c40"),
            ("triage", "43d6e144eb344c175c9b84808e9767e24655d502dec809509e85ed77f9f64518"),
            ("android_static", "9f672152b854ccae4d96351c91a69e35d426250ac1a9e2de16caaf429a8d4902"),
        ],
    )
    def test_every_seed_prompt_a_release_shipped_is_listed(self, key: str, digest: str) -> None:
        assert digest in FORMER_SEED_PROMPT_DIGESTS[key]

    @pytest.mark.parametrize("key", ["reverser", "triage", "android_static"])
    def test_a_row_holding_the_former_reputation_rule_is_the_seed(self, key: str) -> None:
        """The seed's prompt with its former reputation paragraph is read as the
        seed: the row keeps its key and runs the current text."""
        prompt = {
            "reverser": prompts.REVERSER_PROMPT,
            "triage": prompts.TRIAGE_PROMPT,
            "android_static": prompts.ANDROID_STATIC_PROMPT,
        }[key]
        assert _CURRENT_REPUTATION_PARAGRAPH in prompt
        former = prompt.replace(_CURRENT_REPUTATION_PARAGRAPH, _FORMER_REPUTATION_PARAGRAPH)
        assert hashlib.sha256(former.encode()).hexdigest() in FORMER_SEED_PROMPT_DIGESTS[key]
        row = Settings(_env_file=None).agents.definitions[key].model_dump(mode="json")
        row["prompt"] = former

        cfg = Settings(_env_file=None, agents={"definitions": {key: row}})

        assert f"{key}_custom" not in cfg.agents.definitions
        assert cfg.agents.definitions[key].prompt == prompt

    def test_only_seeded_keys_are_listed(self) -> None:
        seeded = set(Settings(_env_file=None).agents.definitions)
        assert set(FORMER_SEED_PROMPT_DIGESTS) <= seeded

    def test_the_normaliser_leaves_every_other_field_alone(self) -> None:
        entry = {"role": "generic", "enabled": False, "tools": [], "prompt": "mine"}
        assert as_stored_builtin("reverser", entry) == {
            "role": "generic",
            "enabled": False,
            "prompt": "mine",
        }


class TestAClonesMissingToolListIsItsRoleSeeds:
    def test_a_static_clone_on_r2_keeps_the_sidecars(self) -> None:
        cfg = Settings(
            _env_file=None,
            agents={"definitions": {"static_r2": {"role": "static", "static_provider": "r2"}}},
        )
        clone = cfg.agents.definitions["static_r2"]
        assert _servers(clone) == _servers(cfg.agents.definitions["static"])
        assert "analysis" in _servers(clone)

    def test_an_explicit_empty_list_means_none(self) -> None:
        cfg = Settings(
            _env_file=None,
            agents={"definitions": {"bare": {"role": "static", "tools": []}}},
        )
        assert cfg.agents.definitions["bare"].tools == []

    def test_an_explicit_list_is_the_operator_s(self) -> None:
        cfg = Settings(
            _env_file=None,
            agents={
                "definitions": {
                    "static_r2": {
                        "role": "static",
                        "static_provider": "r2",
                        "tools": [{"kind": "mcp", "server": "analysis"}],
                    }
                }
            },
        )
        assert _servers(cfg.agents.definitions["static_r2"]) == ["analysis"]

    def test_a_generic_agent_has_no_role_seed_to_inherit(self) -> None:
        cfg = Settings(
            _env_file=None,
            agents={"definitions": {"mine": {"role": "generic", "prompt": "p"}}},
        )
        assert cfg.agents.definitions["mine"].tools == []

    @pytest.mark.parametrize("role", ["dynamic", "network"])
    def test_every_analyst_role_inherits_the_same_way(self, role: str) -> None:
        cfg = Settings(
            _env_file=None,
            agents={"definitions": {f"{role}_2": {"role": role}}},
        )
        assert _servers(cfg.agents.definitions[f"{role}_2"]) == _servers(
            cfg.agents.definitions[role]
        )

    def test_the_settings_api_stores_the_inherited_list(self) -> None:
        """Stored as a list, so the rule is applied once and what the console
        shows is what the run reads."""
        stored = validate_definitions(
            {"static_r2": {"role": "static", "category": "code_reader", "static_provider": "r2"}},
            servers={"analysis": None, "knowledge": None, "virustotal": None},
        )
        assert stored["static_r2"]["tools"] == [
            {"kind": "mcp", "server": "analysis", "name": None},
            {"kind": "mcp", "server": "knowledge", "name": None},
            {"kind": "capability", "server": None, "name": None, "capability": "reputation"},
        ]

    def test_the_helper_only_fills_a_missing_list(self) -> None:
        assert with_the_role_seed_tools({"role": "static", "tools": []})["tools"] == []
        assert with_the_role_seed_tools({"role": "generic"}) == {"role": "generic"}


def test_the_team_preview_reads_a_staged_clone_as_the_save_will() -> None:
    from app.services.agent_map import staged_definitions

    staged = staged_definitions({"static_r2": {"role": "static", "static_provider": "r2"}})
    assert [ref["server"] or ref.get("capability") for ref in staged["static_r2"]["tools"]] == [
        "analysis",
        "knowledge",
        "reputation",
    ]
    assert staged_definitions({"bare": {"role": "static", "tools": []}})["bare"]["tools"] == []
