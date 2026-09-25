"""Facts: every SBM attribute is a value with a state and evidence (PLAN §8.2).

The four states exist so that *absence is never mistaken for safety* (PLAN §3.1, principle 2):

* ``explicit``: stated in the configuration; carries the lines that stated it.
* ``vendor_default``: not stated; resolved from the vendor pack's ``defaults.yaml`` for this
  OS version; carries a reference to the defaults entry that supplied it.
* ``absent``: not stated and no default is known. No value, no evidence.
* ``unknown``: statements exist but were not understood (unmapped). Carries those lines, so
  the Training Studio can show them.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Self

from pydantic import BaseModel, ConfigDict, Field, PlainSerializer, model_validator


class FactState(StrEnum):
    EXPLICIT = "explicit"
    VENDOR_DEFAULT = "vendor_default"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class Evidence(BaseModel):
    """A pointer from a fact back to the exact source lines and the mapping that read them."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    file: str = Field(min_length=1)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    raw: str
    mapping_id: str | None = None
    mapping_version: int | None = Field(default=None, ge=1)
    approved_by: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.line_end < self.line_start:
            raise ValueError("line_end must be >= line_start")
        if (self.mapping_id is None) != (self.mapping_version is None):
            raise ValueError("mapping_id and mapping_version must be given together")
        return self

    @property
    def mapping_ref(self) -> str | None:
        """``mapping_id@version``, the form shown in reports and the provenance drawer."""
        if self.mapping_id is None:
            return None
        return f"{self.mapping_id}@{self.mapping_version}"


def _sorted_list(value: frozenset[str]) -> list[str]:
    return sorted(value)


# Set-valued attributes (protocols, ciphers, members). Serialised sorted so that the same
# input always produces byte-identical output (PLAN §3.1, principle 5).
StrSet = Annotated[frozenset[str], PlainSerializer(_sorted_list, return_type=list[str])]


class Fact[T](BaseModel):
    """A value plus how we know it. Construct with the classmethods, not directly."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    value: T | None = None
    state: FactState = FactState.ABSENT
    evidence: tuple[Evidence, ...] = ()
    default_source: str | None = None
    """For ``vendor_default`` only: ``<pack>/defaults.yaml#<entry id>``."""

    @model_validator(mode="after")
    def _state_rules(self) -> Self:
        has_value = self.value is not None
        match self.state:
            case FactState.EXPLICIT:
                ok = has_value and bool(self.evidence) and self.default_source is None
                why = "explicit facts need a value and at least one evidence line"
            case FactState.VENDOR_DEFAULT:
                ok = has_value and self.default_source is not None
                why = "vendor_default facts need a value and a default_source"
            case FactState.ABSENT:
                ok = not has_value and not self.evidence and self.default_source is None
                why = "absent facts carry no value, evidence or default_source"
            case FactState.UNKNOWN:
                ok = not has_value and bool(self.evidence) and self.default_source is None
                why = "unknown facts carry no value but must point at the unread lines"
        if not ok:
            raise ValueError(why)
        return self

    @classmethod
    def explicit(cls, value: T, *evidence: Evidence) -> Self:
        return cls(value=value, state=FactState.EXPLICIT, evidence=evidence)

    @classmethod
    def vendor_default(cls, value: T, source: str) -> Self:
        return cls(value=value, state=FactState.VENDOR_DEFAULT, default_source=source)

    @classmethod
    def absent(cls) -> Self:
        return cls()

    @classmethod
    def unknown(cls, *evidence: Evidence) -> Self:
        return cls(state=FactState.UNKNOWN, evidence=evidence)

    @property
    def is_known(self) -> bool:
        """True when a rule may use the value (explicit or a version-scoped vendor default)."""
        return self.state in (FactState.EXPLICIT, FactState.VENDOR_DEFAULT)


def union_evidence(*facts: Fact[Any]) -> tuple[Evidence, ...]:
    """Evidence of a derived fact: the de-duplicated union of its inputs' evidence (§8.3)."""
    seen: dict[tuple[str, int, int, str | None], Evidence] = {}
    for fact in facts:
        for ev in fact.evidence:
            seen.setdefault((ev.file, ev.line_start, ev.line_end, ev.mapping_ref), ev)
    return tuple(sorted(seen.values(), key=lambda e: (e.file, e.line_start, e.line_end)))
