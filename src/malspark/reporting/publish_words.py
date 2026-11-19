"""The fixed words every surface says a value's publish state in.

The analyst report's state after a value the run does not publish, the
narrative prompt's state beside each network value, and the label the report
and the prompt list the published network indicators under. Words only: no
import, so a renderer, a round and a check read one text.
"""

from __future__ import annotations

# The state the analyst report writes after a value the run does not publish, in
# its own fixed words: never the model's, never the table's reason (T-555).
UNPUBLISHED_STATE = "not a published indicator"
# The state beside a value the run publishes, where a list says both.
PUBLISHED_STATE = "a published indicator"
# The kinds the report counts as network indicators, and the label it and the
# narrative prompt write the published ones under.
NETWORK_INDICATOR_KINDS = frozenset(
    {"domain", "ip", "url", "user_agent", "ja3", "ja3s", "email", "sni"}
)
PUBLISHED_NETWORK_LABEL = "Published network indicators"
# What is said where the run publishes no network indicator.
NO_PUBLISHED_NETWORK = "this run publishes no network indicator"
