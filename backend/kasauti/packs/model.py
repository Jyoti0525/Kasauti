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
    JsonValue,
    StringConstraints,
    model_validator,
)

from kasauti.mapping.model import AttrPath, Mapping, Pattern, slot_names
from kasauti.packs.versions import validate_range
from kasauti.rules import regex
from kasauti.rules.derivation import Derivation
from kasauti.rules.enrich import Exposure, Inference
from kasauti.rules.expr import Scalar, attribute_type
from kasauti.rules.model import Role, Rule
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
    """How CLI commands stand for the pack's brace configuration (TODO M2.28). A file of
    commands or a terminal capture is replayed (:mod:`kasauti.mapping.commands`); each
    statement left is a path of words, split into blocks where the pack's own mappings expect
    them (:mod:`kasauti.mapping.setform`), so the same mappings read every form."""

    leaf_lists: tuple[str, ...] = ()
    """Statements that take a list of values in order (``authentication-order [ tacplus
    password ]``). Every ``[ … ]`` set of values is read one value at a time; these are given
    back as one list, their values in order wherever their lines are."""


class Records(_Strict):
    """How a JSON/YAML pack's list items read (TODO M2.31). Cloud exports keep one rule's facts
    in separate fields of one object (``IpProtocol``, ``FromPort``, ``ToPort``), and a mapping
    reads one statement: each list item's scalar fields, and those of the objects inside it
    (``PortRange.From``), are rendered as one statement, ``@`` then each key and value in key
    order. Lists inside the item are rendered as before, beneath it. An object giving a key
    twice is refused (read line by line, with the reason): readers differ on which one counts."""

    names: dict[str, str] = Field(default_factory=dict)
    """List key -> the field that names its items (``SecurityGroups: GroupId`` renders
    ``SecurityGroups sg-0a1b``). Items of other lists, or without that field, are numbered
    from 0 in the order the file lists them."""
    sections: tuple[str, ...] = ()
    """The top-level keys a whole export holds (``SecurityGroups``, ``NetworkAcls``). A file
    without one of them holds only part of what is audited, and is read as partial: no rule
    passes on what it doesn't show."""


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
    records: Records | None = None
    """JSON/YAML only: list items read as records (a cloud export's rules)."""
    description: str = ""
    learning: bool = False
    """The pack is still being taught in the Training Studio: it doesn't yet read every area the
    rules judge, so a fact it has no mapping for is never taken as absent (PLAN §11). A reviewed
    pack reads what applies to its vendor; there, a missing attribute means the setting isn't
    there (a Cisco filter has no application match)."""

    @model_validator(mode="after")
    def _set_form_needs_blocks(self) -> Self:
        if self.set_form is not None and self.shape_family is not ShapeFamily.BRACE:
            raise ValueError("set_form rebuilds a brace tree: shape_family must be brace")
        if self.records is not None and self.shape_family is not ShapeFamily.JSON_YAML:
            raise ValueError("records are for JSON/YAML packs: shape_family must be json_yaml")
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
    field: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_.]*$")
    """Instead of ``pattern`` or ``regex``, for packs that read records (``Records``): the
    value of this field in a record in ``context`` (``VpcId`` in ``@ … VpcId vpc-1a2b``)."""
    context: tuple[Pattern, ...] = ()
    all_agree: bool = False
    """Every place the field's ``all_agree`` sources find it must give the same value, or the
    field is left unset and the report says why. An AWS export names a VPC on every group; one
    spanning several VPCs is no single device's, and naming it after the first would mislabel
    it."""

    @model_validator(mode="after")
    def _captures_value(self) -> Self:
        if sum(x is not None for x in (self.pattern, self.regex, self.field)) != 1:
            raise ValueError("give exactly one of `pattern`, `regex` and `field`")
        if self.pattern is not None and "value" not in slot_names(self.pattern):
            raise ValueError(f"identity pattern {self.pattern!r} must capture a `value` slot")
        if self.regex is not None:
            regex.validate(self.regex)
            if "(?P<value>" not in self.regex:
                raise ValueError("an identity regex needs a named group (?P<value>...)")
            if self.context:
                raise ValueError("`context` applies to patterns, not to raw-line regexes")
        if self.field is not None and self.source != "config":
            raise ValueError("`field` reads a configuration's records")
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


ParamName = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]*$")]
RuleIdText = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9\-]*-\d{2}$")]


class JsonEdit(_Strict):
    """One edit to a JSON/YAML export, for platforms whose commands aren't configuration lines
    (the AWS CLI): the export is changed as the commands would change the platform, so the fix
    can be re-audited. ``at`` is a path of keys; ``{Key=value,Other=value}`` picks the list item
    holding those fields and ``[2]`` the third item. ``remove`` drops the list items under
    ``at`` that hold every field of ``where``; ``set`` puts ``value`` at ``at``; ``append``
    adds ``value`` to the list at ``at``. Values may be objects and lists."""

    op: Literal["remove", "set", "append"]
    at: str = Field(min_length=1)
    where: dict[str, Scalar] = Field(default_factory=dict)
    value: JsonValue = None


class Recipe(_Strict):
    """How one rule's failure is fixed on this vendor (PLAN §14). The first recipe whose
    ``rule``, ``entity`` and ``os_versions`` match a failed finding is used.

    ``change`` is what the administrator types, one command per line, in the vendor's own
    configuration syntax. Templates fill ``{{name}}`` fields from the finding (``{{block}}``,
    ``{{line}}``, ``{{key}}``, ``{{hostname}}``) and leave ``<PARAM>`` site values for the
    administrator; :mod:`kasauti.remediation.engine` documents every field. The same lines are
    applied to a copy of the configuration and re-audited, so what is shown is what is proven.
    Pre-check, verify, save and rollback come from the pack's session (``verify.yaml``) and
    from what the change actually altered."""

    id: EntryId
    rule: RuleIdText
    entity: str | None = None
    """RE2 pattern the finding's entity id must match (``^LocalUser\\[enable\\]$``)."""
    os_versions: VersionRangeText = "*"
    each: str | None = None
    """RE2 pattern over each statement's full path (``^line vty ``, ``^snmp community ``): the
    change (with its edits and rollback) is written once per match, with ``{{line}}`` the
    statement, ``{{block}}`` its outermost block, ``{{path}}`` its full path, ``{{parent}}`` the
    path above it, and each named group of the pattern (``(?P<sg>sg-\\S+)`` → ``{{sg}}``)."""
    each_in: Literal["file", "evidence"] = "file"
    """Where ``each`` looks: the whole configuration, or only the finding's own evidence (the
    catch-all term, not every ``then accept`` in the file)."""
    with_record: str | None = None
    """RE2 pattern over the records beside the matched statement's block, for fields the
    statement itself doesn't carry: an AWS rule's ports, next to the group pair that matched."""
    combine: bool = False
    """Several recipes for one rule and entity, each ``combine``, fix a finding together: one
    per kind of statement behind it (network ACL entries, security group ingress, egress). The
    ones that find nothing to change here are left out."""
    lines: str | None = None
    """RE2 pattern: a ``change`` line holding ``{{lines}}`` is written once per matching
    statement (in the finding's block, if it has one), to remove each (``no {{lines}}``)."""
    change: tuple[str, ...] = Field(min_length=1)
    replaces: tuple[str, ...] = ()
    """Command prefixes the change overwrites in its block (``exec-timeout``)."""
    edits: tuple[JsonEdit, ...] = ()
    """For JSON/YAML platforms only: the export edits the commands stand for."""
    rollback: tuple[str, ...] = ()
    """Written out where the rollback can't be derived from the change (the AWS CLI)."""
    check: tuple[str, ...] = ()
    """The pre-check and verify commands, where the session's can't name what changed (an AWS
    ``describe-security-groups --group-ids {{sg}}``)."""
    note: str | None = None
    """Shown with the fix: what the site must decide, or what to check first."""
    source: Literal["curated", "stig"] = "curated"

    @model_validator(mode="after")
    def _valid(self) -> Self:
        for pattern in (self.entity, self.each, self.lines, self.with_record):
            if pattern is not None:
                regex.validate(pattern)
        if self.each and self.lines:
            raise ValueError("a recipe takes `each` or `lines`, not both")
        if self.with_record and not self.each:
            raise ValueError("`with_record` reads beside an `each` match, so it needs `each`")
        return self


class RecipeFile(_Strict):
    recipes: tuple[Recipe, ...] = ()


# --- verify.yaml -------------------------------------------------------------------------------


class Session(_Strict):
    """How a change is entered, checked and kept on this vendor (PLAN §14.5)."""

    enter: tuple[str, ...] = ()
    """Before the change (``configure terminal``)."""
    exit: tuple[str, ...] = ()
    """After it (``end``)."""
    save: tuple[str, ...] = ()
    """Make it survive a reload (``copy running-config startup-config``); empty where the
    platform saves on its own."""
    save_note: str | None = None
    precheck: tuple[str, ...] = Field(min_length=1)
    """Show the configuration under ``{path}`` (the block or command the change touches, as
    :mod:`kasauti.remediation.editors` gives it) before the change."""
    verify: tuple[str, ...] = Field(min_length=1)
    """The same after it, before saving where the platform has a candidate (Junos, PAN-OS)."""
    rollback: tuple[str, ...] = ()
    """A platform's own undo (Junos ``rollback 1``), used instead of inverse commands."""
    kept_negations: tuple[str, ...] = ()
    """Indent family: ``no`` commands the running configuration keeps as a line
    (``no ip http server``: a feature on by default, turned off). Any other ``no`` command
    removes its line and leaves nothing (``no snmp-server community …``)."""


class Param(_Strict):
    """A value only the site can supply (its syslog server, its NTP key), written ``<NAME>`` in
    a recipe. ``example`` is a documentation value, used only to re-audit the fix."""

    name: ParamName
    means: str = Field(min_length=1)
    example: str = Field(min_length=1)


class VerifyFile(_Strict):
    session: Session | None = None
    params: tuple[Param, ...] = ()


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


Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class Control(_Strict):
    id: str = Field(min_length=1)
    title: str = ""
    """Official title where the licence allows (NIST, STIG); our own short wording for ISO/CIS."""
    benchmark: str | None = None
    """The benchmark (one vendor STIG) the control belongs to, for frameworks that have them."""
    severity: Literal["high", "medium", "low"] | None = None
    """STIG category as DISA rates it: high = CAT I, medium = CAT II, low = CAT III."""
    vuln_id: str | None = None
    """STIG Vulnerability ID (``V-215807``), the number DISA's own checklists (CKL) key on."""
    ccis: tuple[str, ...] = ()
    nist: tuple[str, ...] = ()
    """The official bridge to NIST SP 800-53 r5: through the control's CCIs (DISA CCI list) for
    a STIG, through NIST OLIR #155 for ISO/IEC 27001. The crosswalk lint checks every mapping
    against it."""
    fix: str | None = None
    """DISA's fix text (public domain), shown with our fix as reference wording (M4.04)."""


class Source(_Strict):
    title: str
    version: str
    url: str
    sha256: Sha256
    released: str | None = None


class Benchmark(_Strict):
    id: str = Field(min_length=1)
    title: str
    version: str
    """``V3R7``: DISA's version and release."""
    released: str
    vendors: tuple[Slug, ...] = Field(min_length=1)
    """The vendor packs whose devices this benchmark covers."""
    source: Source
    sunset: bool = False
    """DISA has retired the benchmark; kept because no successor exists yet."""


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
    benchmarks: tuple[Benchmark, ...] = ()
    """Per-vendor benchmarks (DISA STIG). Empty: the framework is the same for every vendor."""
    bridge: Source | None = None
    """Where each control's ``nist`` comes from (the DISA CCI list, NIST OLIR #155)."""
    withdrawn: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    """Withdrawn control -> where the official catalog says it went (NIST: moved to or
    incorporated into). Never citable itself."""
    controls: tuple[Control, ...]

    @model_validator(mode="after")
    def _unique(self) -> Self:
        ids = [c.id for c in self.controls]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate control ids in catalog")
        known = {b.id for b in self.benchmarks}
        if len(known) != len(self.benchmarks):
            raise ValueError("duplicate benchmark ids in catalog")
        stray = sorted(
            {c.benchmark for c in self.controls if c.benchmark and c.benchmark not in known}
        )
        if stray or (known and any(c.benchmark is None for c in self.controls)):
            raise ValueError(f"controls outside the catalog's benchmarks: {stray or 'none given'}")
        return self

    def benchmarks_for(self, vendor: str) -> tuple[Benchmark, ...]:
        return tuple(b for b in self.benchmarks if vendor in b.vendors)


class CrosswalkEntry(_Strict):
    rule: str
    controls: tuple[str, ...] = Field(min_length=1)
    source: Literal["authored", "olir-155", "stig-cci", "semantic-proposal"]
    vendor: Slug | None = None
    """For per-vendor frameworks (DISA STIG): the vendor pack whose benchmark ``controls`` are in.
    ``None``: the mapping holds for every vendor."""
    covers: Literal["full", "part", "stricter"] = "full"
    """How much of each control the rule decides. ``full``: the rule's verdict is the control's.
    ``part``: the rule checks part of it (a FAIL fails the control; a PASS proves nothing more).
    ``stricter``: the rule asks for more (a PASS meets the control; a FAIL may not break it)."""
    note: str = ""
    """What the rule leaves out of the control, or asks beyond it."""
    bridge_note: str = ""
    """Required when no NIST control of the rule shares a base control with the framework
    control's official NIST bridge (CCI, OLIR): why the mapping holds anyway."""
    reviewed_by: str | None = None

    @model_validator(mode="after")
    def _explained(self) -> Self:
        if self.covers != "full" and not self.note:
            raise ValueError(f"{self.rule}: a {self.covers!r} mapping needs a note saying why")
        return self


class Crosswalk(_Strict):
    format_version: Literal[1]
    framework: Slug
    entries: tuple[CrosswalkEntry, ...] = ()
