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
from kasauti.rules import regex
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


class SetForm(_Strict):
    """How ``set`` commands stand for the pack's brace configuration (TODO M2.28). Each line is
    the full path to one statement; it is split into blocks where the pack's own mappings
    expect them (:mod:`kasauti.mapping.setform`), so the same mappings read both forms."""

    leaf_lists: tuple[str, ...] = ()
    """Statements that take a list of values in order (``authentication-order [ tacplus
    password ]``). Consecutive lines giving one value each are joined back into one list."""


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
    set_form: SetForm | None = None
    """The configuration can also come as ``set`` commands (Junos ``display set``)."""
    description: str = ""

    @model_validator(mode="after")
    def _set_form_needs_blocks(self) -> Self:
        if self.set_form is not None and self.shape_family is not ShapeFamily.BRACE:
            raise ValueError("set_form rebuilds a brace tree: shape_family must be brace")
        return self


# --- detect.yaml -------------------------------------------------------------------------------


PatternKind = Literal["contains", "line_prefix", "regex", "json_key", "xml_path"]


class Signature(_Strict):
    id: EntryId
    kind: PatternKind
    pattern: str = Field(min_length=1)
    weight: float = Field(gt=0, le=1)


class InputWarning(_Strict):
    """A pattern that says the file isn't what the audit expects (a PAN-OS Panorama export
    rather than a firewall's configuration). A match adds ``message`` to the audit's warnings;
    it never changes a verdict."""

    id: EntryId
    kind: PatternKind
    pattern: str = Field(min_length=1)
    message: str = Field(min_length=20)


class Exclusion(_Strict):
    """A pattern that says the file is another OS the pack isn't written for (Cisco NX-OS,
    against the IOS XE pack), where no pack for that OS is installed to outscore it. A match
    makes the fingerprint not confident, whatever it scores, so the operator is asked; if the
    operator chooses the pack anyway, ``message`` is a warning."""

    id: EntryId
    kind: PatternKind
    pattern: str = Field(min_length=1)
    message: str = Field(min_length=20)


class DetectSpec(_Strict):
    signatures: tuple[Signature, ...] = Field(min_length=1)
    min_score: float = Field(default=0.5, gt=0, le=10)
    warnings: tuple[InputWarning, ...] = ()
    excludes: tuple[Exclusion, ...] = ()


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
    pattern: Pattern | None = None
    """Mapping-language pattern whose ``value`` slot holds the field, e.g.
    ``hostname <STR:value>``."""
    regex: str | None = None
    """Instead of ``pattern``: an RE2 expression with a named group ``value``, matched against
    each raw line, comments included. For identity that vendors print in comment headers:
    EOS ``! device: leaf1 (DCS-7050SX3, EOS-4.30.1F)``, FortiGate ``#config-version=…``."""
    context: tuple[Pattern, ...] = ()

    @model_validator(mode="after")
    def _captures_value(self) -> Self:
        if (self.pattern is None) == (self.regex is None):
            raise ValueError("give exactly one of `pattern` and `regex`")
        if self.pattern is not None and "value" not in slot_names(self.pattern):
            raise ValueError(f"identity pattern {self.pattern!r} must capture a `value` slot")
        if self.regex is not None:
            regex.validate(self.regex)
            if "(?P<value>" not in self.regex:
                raise ValueError("an identity regex needs a named group (?P<value>...)")
            if self.context:
                raise ValueError("`context` applies to patterns, not to raw-line regexes")
        return self


CompanionKind = Literal[
    "show_version",
    "show_inventory",
    "get_system_status",
    "show_system_info",
    "show_chassis_hardware",
    "display_version",
    "display_esn",
]
"""Command outputs that accompany a configuration (PLAN §5.1): the reliable source of serials
and hardware, which configurations rarely hold."""
INVENTORY_GROUPS = ("name", "description", "part", "version", "serial")


class InventoryRecord(_Strict):
    """One hardware component per match, from a companion output (R-07a "hardware details").

    ``record`` is an RE2 expression searched over the whole output, so one record may span
    lines (Cisco ``show inventory`` prints ``NAME:``/``DESCR:`` on one line and ``PID:``/``SN:``
    on the next). Named groups: ``name`` and ``serial`` are required; ``description``,
    ``part`` and ``version`` are optional. A component whose serial comes out empty, or is one
    of ``not_serials`` (Junos prints ``BUILTIN`` for a part with no serial of its own), is
    skipped.
    """

    source: CompanionKind
    record: str = Field(min_length=1)
    not_serials: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _names_its_groups(self) -> Self:
        regex.validate(self.record)
        groups = set(regex.group_names(self.record))
        if not {"name", "serial"} <= groups:
            raise ValueError("an inventory record needs named groups (?P<name>…) and (?P<serial>…)")
        if unknown := groups - set(INVENTORY_GROUPS):
            raise ValueError(f"unknown inventory group(s): {', '.join(sorted(unknown))}")
        return self


class IdentitySpec(_Strict):
    fields: dict[IdentityField, tuple[IdentitySource, ...]]
    companions: dict[CompanionKind, DetectSpec] = Field(default_factory=dict)
    """How to recognise each companion output this pack reads (TODO M2.05): the same
    signatures and scoring as the vendor fingerprint in ``detect.yaml``."""
    inventory: tuple[InventoryRecord, ...] = ()

    @model_validator(mode="after")
    def _every_companion_is_recognisable(self) -> Self:
        used = {s.source for sources in self.fields.values() for s in sources}
        used |= {r.source for r in self.inventory}
        used.discard("config")
        if missing := sorted(used - set(self.companions)):
            raise ValueError(
                f"`companions` needs signatures for {', '.join(missing)}: a source that can't "
                "be recognised is never read"
            )
        return self


# --- defaults.yaml (PLAN §8.2, §9.4) -----------------------------------------------------------


class DefaultEntry(_Strict):
    """What holds when the configuration says nothing, for an OS version range.

    Two forms:

    * ``attr`` + ``value``: an attribute's default (``MgmtSession.idle_timeout_s = 600``).
      With ``entity_key`` it names one entity (``MgmtService`` ``telnet``) and materialises it
      if the config never mentions it; without, it fills that attribute on every entity of
      the type (or on the singleton), except those named in ``except_keys`` (a default for
      FortiOS's configured NTP servers doesn't describe the implicit FortiGuard source), or
      only those whose key starts with ``key_prefix`` (FortiOS's IPv4 routes, ``static:…``,
      default to ``0.0.0.0/0`` and its IPv6 routes, ``static6:…``, to ``::/0``).
    * ``none_of``: the vendor ships *no* entities of this type (no SNMP communities until
      one is configured). Only this lets a rule treat "none seen" as "none exist".
    """

    id: EntryId
    attr: AttrPath | None = None
    entity_key: str | None = None
    except_keys: tuple[str, ...] = ()
    key_prefix: str | None = Field(default=None, min_length=1)
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
            if (
                self.value is not None
                or self.entity_key is not None
                or self.except_keys
                or self.key_prefix is not None
            ):
                raise ValueError(
                    "`none_of` takes no `value`, `entity_key`, `except_keys` or `key_prefix`"
                )
            if self.none_of not in ENTITY_TYPES or self.none_of in SINGLETON_TYPES:
                raise ValueError(f"none_of: {self.none_of!r} is not a multi-entity type")
            return self
        if self.value is None:
            raise ValueError("`attr` needs a `value`")
        entity_type, attr = str(self.attr).split(".", 1)
        kind = attribute_type(entity_type, attr)
        if kind is None or attr == "key":
            raise ValueError(f"{self.attr}: no such SBM attribute")
        narrowed = self.entity_key is not None or self.except_keys or self.key_prefix is not None
        if entity_type in SINGLETON_TYPES and narrowed:
            raise ValueError(
                f"{entity_type} is a singleton; drop `entity_key`/`except_keys`/`key_prefix`"
            )
        if self.entity_key is not None and (self.except_keys or self.key_prefix is not None):
            raise ValueError(
                "`except_keys` and `key_prefix` narrow a default for every entity; "
                "they don't go with `entity_key`"
            )
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
