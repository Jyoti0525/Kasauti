"""Pack file schemas (PLAN §4.4). Frozen at format_version 1 in M0.

Packs are *data only*: schema-validated YAML/JSON, no code, no pickle. A new vendor is a new
vendor pack; a new standard is a framework pack; a new OS version is version-scoped entries.
"""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

from kasauti.mapping.model import AttrPath, Mapping, Pattern
from kasauti.packs.versions import validate_range
from kasauti.rules.derivation import Derivation
from kasauti.rules.expr import Scalar
from kasauti.rules.model import Domain, FixIntent, Rule
from kasauti.shape.model import ShapeFamily

FORMAT_VERSION = 1

Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_]*$")]
"""Pack and framework ids: underscores only, because they prefix mapping ids."""
EntryId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_\-]*$")]
"""Ids of entries inside a pack (signatures, defaults, recipes)."""
VersionRangeText = Annotated[str, AfterValidator(validate_range)]


class _Strict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)


# --- vendors/<vendor_os>/pack.yaml -------------------------------------------------------------


class VendorManifest(_Strict):
    format_version: Literal[1]
    id: Slug
    """``<vendor>_<os>``, e.g. ``cisco_ios_xe``; also the prefix of every mapping id."""
    name: str
    vendor: str
    os_family: str
    shape_family: ShapeFamily
    pack_version: int = Field(ge=1)
    negation_words: tuple[str, ...] = ()
    """Leading words that negate a statement (``no``, ``undo``, ``unset``, ``delete``…)."""
    comment_markers: tuple[str, ...] = ()
    time_unit: Literal["seconds", "minutes"] = "seconds"
    """The vendor's usual unit for bare timeouts; mappings still state units explicitly."""
    description: str = ""


# --- detect.yaml -------------------------------------------------------------------------------


class Signature(_Strict):
    id: EntryId
    kind: Literal["contains", "line_prefix", "regex", "json_key", "xml_path"]
    pattern: str = Field(min_length=1)
    weight: float = Field(gt=0, le=1)


class DetectSpec(_Strict):
    signatures: tuple[Signature, ...] = Field(min_length=1)
    min_score: float = Field(default=0.5, gt=0, le=10)


# --- identity.yaml (PLAN §7) -------------------------------------------------------------------

IdentityField = Literal["hostname", "vendor", "os_version", "model", "serial", "hardware"]
IdentitySourceKind = Literal[
    "config",
    "show_version",
    "show_inventory",
    "get_system_status",
    "show_system_info",
    "show_chassis_hardware",
    "display_version",
    "display_esn",
]


class IdentitySource(_Strict):
    source: IdentitySourceKind
    pattern: Pattern
    """Mapping-language pattern whose ``value`` slot holds the field, e.g.
    ``hostname <STR:value>``."""
    context: tuple[Pattern, ...] = ()


class IdentitySpec(_Strict):
    fields: dict[IdentityField, tuple[IdentitySource, ...]]


# --- defaults.yaml (PLAN §8.2, §9.4) -----------------------------------------------------------


class DefaultEntry(_Strict):
    id: EntryId
    attr: AttrPath
    entity_key: str | None = None
    """Which entity the default applies to (``telnet`` for MgmtService.enabled); None for
    singletons or "every entity of this type"."""
    value: Scalar | tuple[Scalar, ...]
    os_versions: VersionRangeText = "*"
    source: Literal["vendor_manual", "vendor_doc", "curated"]
    reference: str = Field(min_length=3)
    """Where the default is documented (manual section, doc URL). Required: defaults decide
    verdicts, so they must be traceable."""


class DefaultsFile(_Strict):
    defaults: tuple[DefaultEntry, ...] = ()


# --- mappings/*.yaml ---------------------------------------------------------------------------


class MappingFile(_Strict):
    mappings: tuple[Mapping, ...] = ()


# --- recipes/*.yaml (PLAN §14) -----------------------------------------------------------------


class RecipeSteps(_Strict):
    precheck: tuple[str, ...] = Field(min_length=1)
    change: tuple[str, ...] = Field(min_length=1)
    verify: tuple[str, ...] = Field(min_length=1)
    save: tuple[str, ...] = ()
    rollback: tuple[str, ...] = Field(min_length=1)


class Recipe(_Strict):
    id: EntryId
    fix_intent: FixIntent
    os_versions: VersionRangeText = "*"
    steps: RecipeSteps
    """Jinja2 templates rendered in a SandboxedEnvironment with the entities in evidence."""
    expect: str | None = None
    source: Literal["curated", "stig"] = "curated"


class RecipeFile(_Strict):
    recipes: tuple[Recipe, ...] = ()


# --- verify.yaml -------------------------------------------------------------------------------


class VerifyCommands(_Strict):
    precheck: tuple[str, ...] = Field(min_length=1)
    verify: tuple[str, ...] = Field(min_length=1)


class VerifyFile(_Strict):
    domains: dict[Domain, VerifyCommands] = Field(default_factory=dict)


# --- rules/*.yaml and derivations/*.yaml ---------------------------------------------------------


class RuleFile(_Strict):
    rules: tuple[Rule, ...] = ()


class DerivationFile(_Strict):
    derivations: tuple[Derivation, ...] = ()


# --- frameworks/<framework>/ -------------------------------------------------------------------


class Control(_Strict):
    id: str = Field(min_length=1)
    title: str = ""
    """Official title where the licence allows (NIST, STIG); our own short wording for ISO/CIS."""


class FrameworkCatalog(_Strict):
    format_version: Literal[1]
    framework: Slug
    title: str
    version: str
    source_url: str
    licence: str
    retrieved: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    controls: tuple[Control, ...]

    @model_validator(mode="after")
    def _unique(self) -> Self:
        ids = [c.id for c in self.controls]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate control ids in catalog")
        return self


class CrosswalkEntry(_Strict):
    rule: str
    controls: tuple[str, ...] = Field(min_length=1)
    source: Literal["authored", "olir-155", "stig-cci", "semantic-proposal"]
    reviewed_by: str | None = None


class Crosswalk(_Strict):
    format_version: Literal[1]
    framework: Slug
    entries: tuple[CrosswalkEntry, ...] = ()
