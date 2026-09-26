"""Load and validate packs from disk (PLAN §4.4).

M0 scope: schema validation, data-only enforcement and cross-file consistency. Ed25519
signature verification and quarantine of unsigned packs arrive in M5 (TODO M5.08).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ValidationError

from kasauti.mapping.model import Mapping
from kasauti.packs.model import (
    Crosswalk,
    DefaultsFile,
    DerivationFile,
    DetectSpec,
    ExposureFile,
    FrameworkCatalog,
    IdentitySpec,
    InferenceFile,
    MappingFile,
    Recipe,
    RecipeFile,
    RuleFile,
    VendorManifest,
    VerifyFile,
)
from kasauti.rules import expr as ex
from kasauti.rules.derivation import Derivation, DerivationError, order_and_check
from kasauti.rules.enrich import Exposure, Inference
from kasauti.rules.model import Rule

DATA_SUFFIXES = frozenset({".yaml", ".yml", ".json", ".md", ".txt", ".html", ".sig"})
"""Everything a pack may contain. Anything else (``.py``, ``.pkl``, binaries) is refused."""

MAX_FILE_BYTES = 5 * 1024 * 1024


class PackError(ValueError):
    def __init__(self, problems: Iterable[str]) -> None:
        self.problems = tuple(problems)
        super().__init__("\n".join(self.problems))


@dataclass(frozen=True)
class VendorPack:
    root: Path
    manifest: VendorManifest
    detect: DetectSpec
    identity: IdentitySpec
    defaults: DefaultsFile
    mappings: tuple[Mapping, ...]
    recipes: tuple[Recipe, ...]
    verify: VerifyFile


@dataclass(frozen=True)
class RuleSet:
    rules: tuple[Rule, ...]
    derivations: tuple[Derivation, ...]
    """In dependency order."""
    inferences: tuple[Inference, ...] = ()
    """In file order: the first inference to fill an attribute wins."""
    exposures: tuple[Exposure, ...] = ()


@dataclass(frozen=True)
class FrameworkPack:
    root: Path
    catalog: FrameworkCatalog
    crosswalk: Crosswalk | None


@dataclass
class _Collector:
    problems: list[str] = field(default_factory=list)

    def load[M: BaseModel](self, path: Path, model: type[M], *, required: bool = True) -> M | None:
        if not path.exists():
            if required:
                self.problems.append(f"{path}: missing")
            return None
        try:
            return model.model_validate(_read(path))
        except ValidationError as err:
            for e in err.errors():
                loc = ".".join(str(p) for p in e["loc"])
                self.problems.append(f"{path}: {loc}: {e['msg']}")
        except (ValueError, yaml.YAMLError) as err:
            self.problems.append(f"{path}: {err}")
        return None


class _NoAliasLoader(yaml.SafeLoader):
    """SafeLoader that refuses anchors/aliases: a few nested aliases can expand into gigabytes
    (billion laughs). Packs are data written by people; they never need them."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            mark = self.peek_event().start_mark  # type: ignore[no-untyped-call]
            raise yaml.composer.ComposerError(
                None, None, "YAML aliases are not allowed in packs", mark
            )
        return super().compose_node(parent, index)


def _read(path: Path) -> Any:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"larger than {MAX_FILE_BYTES} bytes")
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    # _NoAliasLoader is a SafeLoader subclass: no object construction, and no aliases either.
    return yaml.load(text, Loader=_NoAliasLoader) or {}  # noqa: S506  # nosec B506


def _data_only(root: Path) -> list[str]:
    return [
        f"{p}: not allowed in a pack (data only: {sorted(DATA_SUFFIXES)})"
        for p in sorted(root.rglob("*"))
        if p.is_file() and p.suffix.lower() not in DATA_SUFFIXES and not _placeholder(p)
    ]


def _placeholder(path: Path) -> bool:
    """An empty ``.gitkeep`` keeps a directory in git; it can't carry content."""
    return path.name == ".gitkeep" and path.stat().st_size == 0


def _many[M: BaseModel](
    c: _Collector, files: Iterable[Path], model: type[M], pick: Callable[[M], Iterable[Any]]
) -> list[Any]:
    out: list[Any] = []
    for path in sorted(files):
        loaded = c.load(path, model)
        if loaded is not None:
            out.extend(pick(loaded))
    return out


def load_vendor_pack(root: Path) -> VendorPack:
    c = _Collector(_data_only(root))
    manifest = c.load(root / "pack.yaml", VendorManifest)
    detect = c.load(root / "detect.yaml", DetectSpec)
    identity = c.load(root / "identity.yaml", IdentitySpec)
    defaults = c.load(root / "defaults.yaml", DefaultsFile, required=False) or DefaultsFile()
    verify = c.load(root / "verify.yaml", VerifyFile, required=False) or VerifyFile()
    mappings: list[Mapping] = _many(
        c, (root / "mappings").glob("*.yaml"), MappingFile, lambda f: f.mappings
    )
    recipes: list[Recipe] = _many(
        c, (root / "recipes").glob("*.yaml"), RecipeFile, lambda f: f.recipes
    )

    if manifest is not None:
        if manifest.id != root.name:
            c.problems.append(f"{root}: directory name must equal pack id {manifest.id!r}")
        c.problems += [
            f"mapping {m.id}: vendor {m.vendor!r} is not this pack ({manifest.id!r})"
            for m in mappings
            if m.vendor != manifest.id
        ]
    c.problems += _duplicates("mapping", (m.id for m in mappings))
    c.problems += _duplicates("default", (d.id for d in defaults.defaults))
    c.problems += _duplicates("recipe", (r.id for r in recipes))

    if c.problems or manifest is None or detect is None or identity is None:
        raise PackError(c.problems)
    return VendorPack(
        root, manifest, detect, identity, defaults, tuple(mappings), tuple(recipes), verify
    )


def load_ruleset(
    rules_dir: Path,
    derivations_dir: Path,
    inferences_dir: Path | None = None,
    exposures_dir: Path | None = None,
) -> RuleSet:
    """Rules and the vendor-neutral content they depend on. ``inferences/`` and ``exposures/``
    default to siblings of ``rules/`` (``packs/inferences``, ``packs/exposures``)."""
    inferences_dir = inferences_dir or rules_dir.parent / "inferences"
    exposures_dir = exposures_dir or rules_dir.parent / "exposures"
    dirs = [d for d in (rules_dir, derivations_dir, inferences_dir, exposures_dir) if d.exists()]
    c = _Collector([p for d in dirs for p in _data_only(d)])
    derivations = _many(c, derivations_dir.glob("*.yaml"), DerivationFile, lambda f: f.derivations)
    rules = _many(c, rules_dir.glob("*.yaml"), RuleFile, lambda f: f.rules)
    inferences: list[Inference] = _many(
        c, inferences_dir.glob("*.yaml"), InferenceFile, lambda f: f.inferences
    )
    exposures: list[Exposure] = _many(
        c, exposures_dir.glob("*.yaml"), ExposureFile, lambda f: f.exposures
    )
    ordered: list[Derivation] = []
    try:
        ordered = order_and_check(derivations)
    except DerivationError as err:
        c.problems.append(f"derivations: {err}")
    types: dict[str, ex.Type] = {d.id: d.type for d in derivations}
    by_exposure = {e.id: e for e in exposures}
    for inf in inferences:
        c.problems += [f"inference {inf.id}: {e}" for e in inf.check(types)]
    for exp in exposures:
        c.problems += [f"exposure {exp.id}: {e}" for e in exp.check(types)]
    for rule in rules:
        c.problems += [f"rule {rule.id}: {e}" for e in rule.check(types)]
        entity, _ = rule.scope
        if rule.fix_intent is not None:
            make = rule.fix_intent.make
            if make not in types and ex.attribute_type(entity, make) is None:
                c.problems.append(f"rule {rule.id}: fix_intent.make {make!r} is not a known fact")
        for name in rule.exposure:
            found = by_exposure.get(name)
            if found is None:
                c.problems.append(f"rule {rule.id}: unknown exposure {name!r}")
            elif entity not in found.scopes:
                c.problems.append(
                    f"rule {rule.id}: exposure {name!r} doesn't apply to {entity} "
                    f"(scopes: {', '.join(found.scopes)})"
                )
    c.problems += _duplicates("rule", (r.id for r in rules))
    c.problems += _duplicates("inference", (i.id for i in inferences))
    c.problems += _duplicates("exposure", (e.id for e in exposures))
    if c.problems:
        raise PackError(c.problems)
    return RuleSet(
        tuple(sorted(rules, key=lambda r: r.id)),
        tuple(ordered),
        tuple(inferences),
        tuple(sorted(exposures, key=lambda e: e.id)),
    )


def load_framework_pack(root: Path) -> FrameworkPack:
    c = _Collector(_data_only(root))
    catalog = c.load(root / "catalog.json", FrameworkCatalog)
    crosswalk = c.load(root / "crosswalk.yaml", Crosswalk, required=False)
    if catalog is not None and crosswalk is not None and crosswalk.framework != catalog.framework:
        c.problems.append(f"{root}: crosswalk framework != catalog framework")
    if c.problems or catalog is None:
        raise PackError(c.problems)
    return FrameworkPack(root, catalog, crosswalk)


def _duplicates(what: str, ids: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    dup: list[str] = []
    for ident in ids:
        if ident in seen:
            dup.append(f"{what} id {ident!r} defined more than once")
        seen.add(ident)
    return dup
