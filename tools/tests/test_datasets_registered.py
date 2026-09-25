"""Every dataset file is listed in datasets/SOURCES.md with its exact SHA-256 (TODO S.07)."""

import hashlib
import re
from pathlib import Path

DATASETS = Path(__file__).resolve().parents[2] / "datasets"
IGNORED = {"SOURCES.md", ".gitkeep"}


def test_every_dataset_file_is_registered_with_its_hash() -> None:
    sources = (DATASETS / "SOURCES.md").read_text(encoding="utf-8")
    listed = dict(re.findall(r"\| `([^`]+)` \|[^\n]*?`([0-9a-f]{64})`", sources))
    on_disk = {
        p.relative_to(DATASETS / "authored").as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (DATASETS / "authored").rglob("*")
        if p.is_file() and p.name not in IGNORED
    }
    assert set(on_disk) <= set(listed), f"unlisted files: {sorted(set(on_disk) - set(listed))}"
    wrong = {f: h for f, h in on_disk.items() if listed[f] != h}
    assert not wrong, f"hash mismatch (file changed? update SOURCES.md): {wrong}"
