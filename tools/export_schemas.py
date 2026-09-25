"""Export JSON Schemas for every pack file and the SBM to ``docs/spec/schemas/``.

The Pydantic models are the single source of truth; the JSON Schemas let editors and the future
Training Studio validate files, and document the frozen pack format (PLAN §4.4, TODO M0.21).

Usage: ``uv run python tools/export_schemas.py`` (write) or ``--check`` (CI: fail if stale).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pydantic import BaseModel

from kasauti.packs import model as pm
from kasauti.sbm.document import SecurityBaselineModel

OUT = Path(__file__).resolve().parents[1] / "docs" / "spec" / "schemas"

SCHEMAS: dict[str, type[BaseModel]] = {
    "vendor-pack.schema.json": pm.VendorManifest,
    "detect.schema.json": pm.DetectSpec,
    "identity.schema.json": pm.IdentitySpec,
    "defaults.schema.json": pm.DefaultsFile,
    "mappings.schema.json": pm.MappingFile,
    "recipes.schema.json": pm.RecipeFile,
    "verify.schema.json": pm.VerifyFile,
    "rules.schema.json": pm.RuleFile,
    "derivations.schema.json": pm.DerivationFile,
    "framework-catalog.schema.json": pm.FrameworkCatalog,
    "crosswalk.schema.json": pm.Crosswalk,
    "sbm.schema.json": SecurityBaselineModel,
}


def render(model: type[BaseModel]) -> str:
    schema = model.model_json_schema(by_alias=True, mode="validation")
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if files are out of date")
    args = parser.parse_args(argv)
    stale: list[str] = []
    OUT.mkdir(parents=True, exist_ok=True)
    for name, model in SCHEMAS.items():
        path = OUT / name
        text = render(model)
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == text:
            continue
        if args.check:
            stale.append(name)
        else:
            path.write_text(text, encoding="utf-8", newline="\n")
            print(f"wrote {path.relative_to(OUT.parents[2])}")
    if stale:
        print("stale schemas (run tools/export_schemas.py): " + ", ".join(stale))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
