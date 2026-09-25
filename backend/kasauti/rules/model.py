"""Rule language (v0) and finding types (PLAN §12.1, §12.6, §12.7)."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from kasauti.rules import expr as ex
from kasauti.sbm.entities import ENTITY_TYPES
from kasauti.sbm.facts import Evidence

RULE_ID = r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*-\d{2}$"
"""e.g. ``MGMT-TELNET-01``; the two-digit suffix leaves room for variants."""

NIST_CONTROL = r"^[A-Z]{2}-\d{1,2}(\(\d{1,2}\))?$"
"""SP 800-53 r5 control or enhancement, e.g. ``CM-7`` or ``AC-17(2)``. Existence in the
official catalog is checked by the crosswalk lint, not here (PLAN §12.2)."""


class Domain(StrEnum):
    """The ten rule domains (PLAN §12.3)."""

    MANAGEMENT_PLANE = "management_plane"
    AAA = "aaa"
    LOGGING = "logging"
    TIME = "time"
    SNMP = "snmp"
    SERVICES = "services"
    CRYPTO = "crypto"
    FILTERING = "filtering"
    L2 = "l2"
    ROUTING_AUTH = "routing_auth"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class OnMissing(StrEnum):
    """What a rule does when a fact it needs is ``absent`` or ``unknown``.

    There is deliberately no ``pass`` option: absence is never evidence of safety (§3.1).
    """

    RESOLVE_DEFAULT = "resolve_default"
    """Use the version-scoped vendor default; if none is known, REVIEW. Only for ``on_absent``."""
    REVIEW = "review"
    FAIL = "fail"
    """For rules where absence *is* the violation, e.g. "a remote log host must be set"."""
    NOT_APPLICABLE = "not_applicable"


class Role(StrEnum):
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    CLOUD_FILTER = "cloud_filter"
    WHITE_BOX = "white_box"


class Status(StrEnum):
    # A verdict, not a password (hence the S105/B105 suppressions).
    PASS = "PASS"  # noqa: S105  # nosec B105
    FAIL = "FAIL"
    REVIEW = "REVIEW"
    NOT_APPLICABLE = "N/A"


class _Strict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)


class SeveritySpec(_Strict):
    base: Severity


class FixIntent(_Strict):
    make: str = Field(min_length=1)
    """A derived fact id or an attribute of the rule's entity."""
    equal: ex.Scalar | tuple[ex.Scalar, ...]


NistId = Annotated[str, StringConstraints(pattern=NIST_CONTROL)]


class Refs(_Strict):
    nist_800_53r5: tuple[NistId, ...] = ()
    disa_stig: Literal["auto"] | tuple[str, ...] = ()
    cis: dict[str, str] = Field(default_factory=dict)
    """Benchmark key (``<vendor>_<version>``) -> recommendation ID. IDs only (CC BY-NC-SA)."""
    iso_27001_2022: Literal["derived"] | tuple[str, ...] = "derived"
    """``derived``: via NIST OLIR #155 from the NIST anchors, then reviewed (§12.4)."""


class Fixtures(_Strict):
    pass_: tuple[str, ...] = Field(default=(), alias="pass")
    fail: tuple[str, ...] = ()


class Rule(_Strict):
    id: Annotated[str, StringConstraints(pattern=RULE_ID)]
    title: str = Field(min_length=5)
    intent: str = Field(min_length=5)
    domain: Domain
    applies_to: tuple[Role, ...] = tuple(Role)
    for_each: str
    assert_: str = Field(alias="assert")
    on_absent: OnMissing = OnMissing.REVIEW
    on_unknown: OnMissing = OnMissing.REVIEW
    severity: SeveritySpec
    exposure: tuple[str, ...] = ()
    fix_intent: FixIntent | None = None
    refs: Refs = Field(default_factory=Refs)
    hardening_best_practice: bool = False
    """True for checks with no benchmark behind them; never given an invented control ID."""
    fixtures: Fixtures = Field(default_factory=Fixtures)

    @model_validator(mode="after")
    def _semantics(self) -> Self:
        entity, _ = ex.parse_scope(self.for_each)
        if entity not in ENTITY_TYPES:
            raise ValueError(f"for_each: unknown entity type {entity!r}")
        ex.parse(self.assert_)
        if self.on_unknown is OnMissing.RESOLVE_DEFAULT:
            raise ValueError("on_unknown cannot be resolve_default: defaults only fill absence")
        if not self.refs.nist_800_53r5 and not self.hardening_best_practice:
            raise ValueError(
                "every rule is anchored to NIST SP 800-53 r5 (§12.4); "
                "set hardening_best_practice: true for checks with no benchmark"
            )
        return self

    @property
    def scope(self) -> tuple[str, ex.Expr | None]:
        return ex.parse_scope(self.for_each)

    def check(self, derived: dict[str, ex.Type]) -> list[str]:
        """Full static check once the pack's derived facts are known."""
        entity, where = self.scope
        errors: list[str] = []
        if where is not None:
            errors += [f"for_each: {e}" for e in ex.check(where, scope=entity, derived=derived)]
        errors += [
            f"assert: {e}" for e in ex.check(ex.parse(self.assert_), scope=entity, derived=derived)
        ]
        return errors


class Finding(_Strict):
    """One rule applied to one entity (PLAN §12.1: per-entity findings)."""

    rule_id: str
    entity_id: str
    status: Status
    severity: Severity | None = None
    severity_reason: str | None = None
    """e.g. ``High (base) → Critical: telnet allowed on wan1 (untrusted)`` (§12.7)."""
    reason: str
    evidence: tuple[Evidence, ...] = ()
