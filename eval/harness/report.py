"""Write evaluation reports to ``eval/reports/<run_id>/`` as JSON (for tools) and Markdown
(for people). The run id is passed in, so report content is reproducible."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from harness.metrics import Ratio


def write_report(
    out_dir: Path, run_id: str, title: str, metrics: Mapping[str, Ratio], notes: str = ""
) -> Path:
    target = out_dir / run_id
    target.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_id": run_id,
        "title": title,
        "metrics": {k: {"num": v.num, "den": v.den, "value": v.value} for k, v in metrics.items()},
        "notes": notes,
    }
    (target / "report.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [f"# {title}", "", f"Run `{run_id}`", "", "| Metric | Result |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in metrics.items()]
    if notes:
        lines += ["", notes]
    md = target / "report.md"
    md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return md
