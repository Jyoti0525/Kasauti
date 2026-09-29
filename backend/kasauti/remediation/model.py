"""What the remediator hands the report, the web UI and the CLI (PLAN §14.5)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class _Out(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Proof(StrEnum):
    VERIFIED = "verified"
    """The change was applied to a copy of the configuration and re-audited: the finding it
    targets no longer fails and no other check got worse."""
    NOT_VERIFIED = "not_verified"
    """Re-audited, and it didn't hold: the reason says what still fails or what regressed."""
    NOT_CHECKED = "not_checked"
    """The copy couldn't be re-audited (a file read only in part, say): shown, never claimed."""


class Step(_Out):
    commands: tuple[str, ...]
    """Secrets from the configuration are masked (``****``); the note says where they are."""
    note: str | None = None


class Placeholder(_Out):
    name: str
    means: str


class Fix(_Out):
    """One failed check fixed on this device: every entity it fails for, in one change."""

    rule_id: str
    entity_ids: tuple[str, ...]
    """The findings it fixes (``Interface[Gi1]``, ``Interface[Gi2]`` …); a device-wide
    finding's is ``Device[device]``."""
    recipe: str
    """``<pack>/<recipe id>``, so every command can be traced to reviewed pack content."""
    source: str
    precheck: Step
    change: Step
    verify: Step
    save: Step | None
    rollback: Step
    placeholders: tuple[Placeholder, ...] = ()
    """Values the site fills in before use (``<SYSLOG_SERVER>``)."""
    note: str | None = None
    proof: Proof
    proof_detail: str


class FleetFix(_Out):
    """Every fix applied together to one copy and re-audited: the posture after remediation."""

    proof: Proof
    detail: str
    failed_before: int
    failed_after: int
    compliance_after_pct: float | None = None
    still_failing: tuple[str, ...] = ()
    """Rules that still fail with every verified fix applied: those needing a site decision
    Kasauti can't make, or whose fixes undo each other."""
    left_for_review: tuple[str, ...] = ()
    """Rules that failed before and, with every fix applied, can't be judged from the file
    alone: each fixed on its own, but together they leave a question only a person can answer
    (PAN-OS: once administrators log in through an authentication profile, which lockout
    governs isn't documented)."""


class Remediation(_Out):
    fixes: tuple[Fix, ...] = ()
    unfixed: tuple[str, ...] = ()
    """``rule_id [entity]`` of failures no recipe covers, with why, so none is silently dropped."""
    combined: FleetFix | None = None
    basis: str = (
        "Verified against Kasauti's model of this device (the changed configuration re-parsed and "
        "re-audited), not on hardware. Review each change, fill in the <values>, and test it in a "
        "maintenance window. Kasauti never applies a change to a device."
    )
