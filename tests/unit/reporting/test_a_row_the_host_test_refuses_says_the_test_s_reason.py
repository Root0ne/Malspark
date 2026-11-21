"""A row the host test refuses says the publish rule's finding: the test's own reason.

A domain, a URL or a mailbox row the host test refuses is answered with the reason
the deciding function gives (``network_extractor.host_failure``, ``url_failure``,
``stix_renderer.email_failure``), under the family's one subject, the publish
rule; no renderer words a host reason of its own, and the decision is that
function. Every quoted span is the reason writer's, so the answer holds no ";" and
no raw quote or control character, and its first ";" clause is the whole answer.
Every value is synthetic.
"""

from __future__ import annotations

import pytest

from malspark.extractors.network_extractor import host_failure, url_failure
from malspark.pipeline.validation import _states_publish_state
from malspark.reporting.renderers.stix_renderer import email_failure, publish_answer, publishes

FOUND = "no: the publish rule found that "


@pytest.mark.parametrize(
    ("kind", "value", "reason"),
    [
        (
            "url",
            "http://ocsp.example.com0",
            'its host fails the host test: its last label "com0" is neither two or more letters '
            "a-z nor an xn-- label",
        ),
        (
            "domain",
            "INTRANET",
            'it fails the host test: "intranet" (read in lower case) is a single label',
        ),
        (
            "domain",
            "\\\\.\\pipe\\x",
            'it fails the host test: its label "{U+005C}{U+005C}" holds "{U+005C}" (U+005C), '
            "which is not a letter a-z, a digit or a hyphen",
        ),
        (
            "url",
            "ocsp.x/y",
            "it is not a URL — it has no scheme — so there is no host in it to ask about",
        ),
        ("url", "mailto:x@a.com", 'it holds no "://", so there is no host in it to ask about'),
        ("url", "http://[::1/", "the URL parser could not read its host"),
        (
            "email",
            "x@a.com0",
            'its domain part fails the host test: its last label "com0" is neither two or more '
            "letters a-z nor an xn-- label",
        ),
        (
            "email",
            "x@localhost",
            'its domain part fails the host test: "localhost" is a single label',
        ),
        ("email", "x..y@a.com", "it is not a mailbox by its syntax"),
        ("email", "x@a_b.com", "it is not a mailbox by its syntax"),
    ],
)
def test_the_answer_is_the_test_s_reason(kind: str, value: str, reason: str) -> None:
    answer = publish_answer(kind, value, "strings", None)

    assert answer == FOUND + reason
    assert not publishes(answer)
    # The decision is the reason function's.
    failure = {"url": url_failure, "domain": host_failure, "email": email_failure}[kind](value)
    assert failure and failure in reason


@pytest.mark.parametrize(
    "value",
    [
        "http://a;b.com/x",
        "x;y",
        'a"b.com',
        "a‮b.com",
        "a​b.com",
        "a`b.com",
        "\\\\.\\pipe\\x",
        "a" + ";" * 70 + ".com",
    ],
)
def test_a_hostile_value_is_answered_on_one_line_with_no_mark_of_its_own(value: str) -> None:
    kind = "url" if "://" in value else "domain"
    answer = str(publish_answer(kind, value, "strings", None))

    assert answer.startswith(FOUND)
    assert ";" not in answer and answer.isprintable()
    assert len(answer) <= 200
    # A writer restating the answer in brackets restates it.
    assert _states_publish_state(
        f" ({answer[4:]}) was read.", publish_answer(kind, value, "strings", None)
    )


def test_a_name_the_host_test_passes_is_not_refused_by_it() -> None:
    answer = str(publish_answer("domain", "example.com", "strings", None))
    assert "host test" not in answer
