"""A number list after a hyphenated name is one name, not values.

A claim that writes "SHA-1/2/512" names three variants of one name. The
"-1" was never read as a value, but the "/2" and "/512" were, so a retry
that wrote "SHA-1, SHA-2, SHA-512" was asked about "512". Now only the
``/<m>`` parts of a ``<name>-<n>/<m>[/...]`` list are not read; every other
number after "/" is read as before ("UDP/53", "proc:85/89", "443/tcp").
Every value is synthetic.
"""

from __future__ import annotations

import pytest

from malspark.pipeline.claim_drops import claim_values, dropped_claims, dropped_values
from malspark.schemas.isr_models import AgentISR, ClaimEvidence


def _isr(*claims: str) -> AgentISR:
    return AgentISR(
        agent_id="beta",
        domain="static",
        claims=[ClaimEvidence(claim=c, evidence_ref="[ev_0001]", confidence=0.8) for c in claims],
    )


@pytest.mark.parametrize(
    "text",
    [
        "The crypto constants (SHA-1/2/512, MD5) are library code.",
        "capa reports SHA-256/384/512 routines.",
    ],
)
def test_a_variant_list_after_a_hyphenated_name_yields_no_value(text: str) -> None:
    assert not {v for v in claim_values(text) if v.isdecimal()}


@pytest.mark.parametrize(
    ("text", "numbers"),
    [
        ("The UDP/53 flow to the resolver.", {"53"}),
        ("A TCP/443 session opens.", {"443"}),
        ("The beacon (TCP/80) repeats.", {"80"}),
        ("Two children proc:85/89 start.", {"85", "89"}),
        ("The local var_e4/100 divides.", {"100"}),
        ("The dump memory/4772-12 is read.", {"4772"}),
        ("It listens on 443/tcp.", {"443"}),
        ("It listens on port 443.", {"443"}),
    ],
)
def test_every_other_number_after_a_slash_is_read_as_before(text: str, numbers: set[str]) -> None:
    assert numbers <= claim_values(text)


def test_a_retry_that_writes_each_variant_whole_drops_nothing() -> None:
    first = _isr("The crypto constants (SHA-1/2/512, MD5) sit at 0x5720.")
    retry_text = "The crypto constants (SHA-1, SHA-2, SHA-512, MD5) sit at 0x5720."
    retry = _isr(retry_text)

    assert dropped_values(first, retry, retry_text) == []
    assert dropped_claims(first, retry, retry_text) == []


def test_a_real_number_beside_a_variant_list_is_still_asked() -> None:
    first = _isr("SHA-1/256/512 constants; the parent is pid 1972.")
    retry_text = "SHA-1, SHA-256 and SHA-512 constants; the parent is pid 416."
    retry = _isr(retry_text)

    [(_claim, missing)] = dropped_claims(first, retry, retry_text)
    assert missing == ("1972",)
