"""Checks a vendor pack's recipes against the rule set, when the knowledge base loads.

A recipe for a rule that doesn't exist would never be used, and a ``<PARAM>`` the pack doesn't
describe would reach an administrator with no explanation, so either stops the load, the way a
mapping to an unknown attribute does.
"""

from __future__ import annotations

import re

from kasauti.packs.loader import RuleSet, VendorPack

_PARAM = re.compile(r"<([A-Z][A-Z0-9_]*)>")


def recipe_problems(pack: VendorPack, ruleset: RuleSet) -> list[str]:
    where = f"{pack.root.name}/recipes"
    rules = {r.id for r in ruleset.rules}
    described = {p.name for p in pack.verify.params}
    problems: list[str] = []
    if pack.recipes and pack.verify.session is None:
        problems.append(f"{where}: recipes need a session in verify.yaml (how to enter and save)")
    seen: set[str] = set()
    for recipe in pack.recipes:
        if recipe.id in seen:
            problems.append(f"{where}: recipe id {recipe.id!r} is used twice")
        seen.add(recipe.id)
        if recipe.rule not in rules:
            problems.append(f"{where}/{recipe.id}: no rule {recipe.rule!r} in the rule set")
        text = " ".join(
            (
                *recipe.change,
                *recipe.rollback,
                *recipe.check,
                *(e.model_dump_json() for e in recipe.edits),
            )
        )
        for name in sorted(set(_PARAM.findall(text)) - described):
            problems.append(f"{where}/{recipe.id}: <{name}> isn't described in verify.yaml params")
    return problems
