"""``uv run python -m harness status``: show which evaluation datasets are populated."""

from __future__ import annotations

import sys

from harness.datasets import DATASETS


def main(argv: list[str]) -> int:
    if argv[:1] != ["status"]:
        print("usage: python -m harness status")
        return 2
    print(f"{'id':<4} {'dataset':<13} {'files':>5}  populated in")
    for ds in DATASETS:
        print(f"{ds.id:<4} {ds.name:<13} {len(ds.files()):>5}  {ds.milestone}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
