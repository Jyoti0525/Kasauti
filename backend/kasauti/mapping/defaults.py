"""Version-scoped vendor defaults (PLAN §8.2, §9.4; TODO M1.07).

A default only fills an attribute that is still *absent* after mapping: never one the config
stated, and never one we saw but couldn't read (*unknown*). Each filled fact is
``vendor_default`` and names the defaults entry, so a report can say "resolved from the vendor
default for 17.9 (``cisco_ios_xe/defaults.yaml#exec-timeout``)".

If the OS version is unknown, only defaults valid for every version (``*``) apply: defaults do
change between releases, and guessing the release could turn a REVIEW into a false PASS.
Conflicting entries for the same target (overlapping ranges, different values) are both
ignored and reported; the attribute stays absent, so the rule says REVIEW.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from kasauti.mapping.builder import SbmBuilder
from kasauti.packs.model import DefaultEntry
from kasauti.packs.versions import VersionRange
from kasauti.sbm.entities import SINGLETON_TYPES


def apply_defaults(
    builder: SbmBuilder,
    defaults: Sequence[DefaultEntry],
    os_version: str | None,
    source_prefix: str = "",
) -> list[str]:
    """Fill absent facts in place; return warnings (conflicting entries)."""
    groups: dict[tuple[str, str | None], list[DefaultEntry]] = defaultdict(list)
    for d in sorted(defaults, key=lambda d: d.id):
        scope = VersionRange.parse(d.os_versions)
        if scope.is_any or (os_version is not None and scope.contains(os_version)):
            if d.none_of:
                target: tuple[str, str | None] = (f"none_of:{d.none_of}", None)
            elif d.key_prefix is not None:
                target = (str(d.attr), f"{d.key_prefix}*")  # its own set of entities
            else:
                target = (str(d.attr), d.entity_key)
            groups[target].append(d)

    warnings: list[str] = []
    for target, entries in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")):
        if len({repr(e.value) for e in entries}) > 1:
            ids = ", ".join(e.id for e in entries)
            warnings.append(
                f"conflicting defaults for {target[0]} ({ids}) at {os_version}; none used"
            )
            continue
        entry = entries[0]
        source = f"{source_prefix}defaults.yaml#{entry.id}"
        if entry.none_of:
            _none_of(builder, entry.none_of, source)
        else:
            _attribute(builder, entry, source)
    return warnings


def _none_of(builder: SbmBuilder, entity_type: str, source: str) -> None:
    if entity_type not in builder.unread and not builder.of_type(entity_type):
        builder.known_empty[entity_type] = source


def _attribute(builder: SbmBuilder, entry: DefaultEntry, source: str) -> None:
    entity_type, attr = str(entry.attr).split(".", 1)
    value: object = entry.value
    if isinstance(entry.value, tuple):
        value = frozenset(str(v) for v in entry.value)
    if entity_type in SINGLETON_TYPES:
        refs = [builder.singleton(entity_type)]
    elif entry.entity_key is not None:
        refs = [(entity_type, entry.entity_key)]
    else:
        refs = [
            r
            for r in builder.of_type(entity_type)
            if r[1] not in entry.except_keys
            and (entry.key_prefix is None or r[1].startswith(entry.key_prefix))
        ]
    for ref in refs:
        builder.entity(ref).fact(attr).default(value, source)
