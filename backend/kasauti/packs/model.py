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

from kasauti.mapping.model import AttrPath, Mapping, Pattern, slot_names
from kasauti.packs.versions import validate_range
from kasauti.rules.derivation import Derivation
from kasauti.rules.enrich import Exposure, Inference
from kasauti.rules.expr import Scalar, attribute_type
from kasauti.rules.model import Domain, FixIntent, Role, Rule
from kasauti.sbm.entities import ENTITY_TYPES, SINGLETON_TYPES
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
    default_role: Role | None = None
    """The device role when no inference decides one (FortiOS: firewall). Recorded as a
    ``vendor_default``, so an inferred or admin-set role always wins (PLAN §7)."""
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

    @model_validator(mode="after")
    def _captures_value(self) -> Self:
        if "value" not in slot_names(self.pattern):
            raise ValueError(f"identity pattern {self.pattern!r} must capture a `value` slot")
        return self


class IdentitySpec(_Strict):
    fields: dict[IdentityField, tuple[IdentitySource, ...]]


# --- defaults.yaml (PLAN §8.2, §9.4) -----------------------------------------------------------


class DefaultEntry(_Strict):
    """What holds when the configuration says nothing, for an OS version range.

    Two forms:

    * ``attr`` + ``value``: an attribute's default (``MgmtSession.idle_timeout_s = 600``).
      With ``entity_key`` it names one entity (``MgmtService`` ``telnet``) and materialises it
      if the config never mentions it; without, it fills that attribute on every entity of
      the type (or on the singleton).
    * ``none_of``: the vendor ships *no* entities of this type (no SNMP communities until
      one is configured). Only this lets a rule treat "none seen" as "none exist".
    """

    id: EntryId
    attr: AttrPath | None = None
    entity_key: str | None = None
    value: Scalar | tuple[Scalar, ...] | None = None
    none_of: str | None = None
    os_versions: VersionRangeText = "*"
    source: Literal["vendor_manual", "vendor_doc", "curated"]
    reference: str = Field(min_length=3)
    """Where the default is documented (manual section, doc URL). Required: defaults decide
    verdicts, so they must be traceable."""

    @model_validator(mode="after")
    def _one_form(self) -> Self:
        if (self.attr is None) == (self.none_of is None):
            raise ValueError("give exactly one of `attr` (with `value`) or `none_of`")
        if self.none_of is not None:
            if self.value is not None or self.entity_key is not None:
                raise ValueError("`none_of` takes no `value` or `entity_key`")
            if self.none_of not in ENTITY_TYPES or self.none_of in SINGLETON_TYPES:
                raise ValueError(f"none_of: {self.none_of!r} is not a multi-entity type")
            return self
        if self.value is None:
            raise ValueError("`attr` needs a `value`")
        entity_type, attr = str(self.attr).split(".", 1)
        kind = attribute_type(entity_type, attr)
        if kind is None or attr == "key":
            raise ValueError(f"{self.attr}: no such SBM attribute")
        if entity_type in SINGLETON_TYPES and self.entity_key is not None:
            raise ValueError(f"{entity_type} is a singleton; drop `entity_key`")
        if not _value_fits(kind, self.value):
            raise ValueError(f"{self.attr} is {kind}-valued; {self.value!r} doesn't fit")
        return self


def _value_fits(kind: str, value: Scalar | tuple[Scalar, ...]) -> bool:
    match kind:
        case "bool":
            return isinstance(value, bool)
        case "int":
            return isinstance(value, int) and not isinstance(value, bool)
        case "str":
            return isinstance(value, str)
        case "set":
            return isinstance(value, tuple) and all(isinstance(v, str) for v in value)
    return False


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


class InferenceFile(_Strict):
    inferences: tuple[Inference, ...] = ()


class ExposureFile(_Strict):
    exposures: tuple[Exposure, ...] = ()


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
    source_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    """SHA-256 of the official file the IDs were extracted from, so the import is verifiable."""
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
