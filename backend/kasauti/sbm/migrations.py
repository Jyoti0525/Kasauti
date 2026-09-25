"""SBM schema migrations (PLAN §8.4).

A stored SBM (golden snapshot, audit history) is upgraded step by step to the current
``SBM_VERSION`` before it is loaded. Each step is a pure function on the raw JSON dict.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from kasauti.sbm.document import SBM_VERSION

RawSBM = dict[str, Any]
Step = Callable[[RawSBM], RawSBM]

# from_version -> (to_version, step). Add one entry per schema change; never edit old steps.
MIGRATIONS: dict[str, tuple[str, Step]] = {}


class MigrationError(ValueError):
    pass


def migrate(
    data: RawSBM,
    *,
    target: str = SBM_VERSION,
    registry: dict[str, tuple[str, Step]] | None = None,
) -> RawSBM:
    """Upgrade ``data`` to ``target``. Raises if no path exists or a step loops."""
    steps = MIGRATIONS if registry is None else registry
    current = str(data.get("sbm_version", ""))
    visited: set[str] = set()
    while current != target:
        if current in visited:
            raise MigrationError(f"migration loop at version {current!r}")
        visited.add(current)
        if current not in steps:
            raise MigrationError(f"no migration from sbm_version {current!r} to {target!r}")
        nxt, step = steps[current]
        data = step(dict(data))
        data["sbm_version"] = nxt
        current = nxt
    return data
