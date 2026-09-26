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


def _v01_to_v02(data: RawSBM) -> RawSBM:
    """0.1 -> 0.2 (M1): entities gain ``evidence``; the document gains ``known_empty`` and
    ``unread``; ``TimePolicy`` is new. All additions default to empty, so 0.1 content is kept
    as-is. A 0.1 ``TimeSource.authenticated`` keeps its meaning (a key is configured)."""
    data.setdefault("known_empty", {})
    data.setdefault("unread", {})
    return data


def _v02_to_v03(data: RawSBM) -> RawSBM:
    """0.2 -> 0.3 (M1 hardening): new optional attributes only (MgmtService.access_filter,
    Interface.description, Interface.proxy_arp, PasswordPolicy.cleartext_passwords_encrypted).
    Absent in older documents, which is exactly what they meant."""
    return data


def _v03_to_v04(data: RawSBM) -> RawSBM:
    """0.3 -> 0.4 (M2): the ``Reference`` entity type and ``ObjectDef.expanded`` are new.
    Older documents had no resolver, so they simply have no references."""
    return data


def _v04_to_v05(data: RawSBM) -> RawSBM:
    """0.4 -> 0.5 (M2, FortiOS): new optional attributes ``PasswordPolicy.enforced`` and
    ``LogTarget.enabled``. Absent in older documents: no platform before FortiOS had a
    separate on/off switch for either, which is exactly what absence means."""
    return data


def _v05_to_v06(data: RawSBM) -> RawSBM:
    """0.5 -> 0.6 (M2, FortiOS gaps): new optional attributes ``LocalUser.permitted_sources``,
    ``LocalUser.permitted_sources_v6``, ``TimeSource.enabled`` and ``TimePolicy.sync_enabled``.
    Absent in older documents, which read no per-account sources and no sync switch."""
    return data


# from_version -> (to_version, step). Add one entry per schema change; never edit old steps.
MIGRATIONS: dict[str, tuple[str, Step]] = {
    "0.1": ("0.2", _v01_to_v02),
    "0.2": ("0.3", _v02_to_v03),
    "0.3": ("0.4", _v03_to_v04),
    "0.4": ("0.5", _v04_to_v05),
    "0.5": ("0.6", _v05_to_v06),
}


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
