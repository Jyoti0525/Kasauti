"""Shape-family detection by scoring structural signals (PLAN §6.1, TODO M2.17).

Each family gets a score in [0, 1] from signals that are cheap to compute and hard to fake by
accident: XML/JSON validity markers, ``config/edit/next/end`` markers, leading ``set`` or ``/``,
brace balance, indentation regularity. Vendor fingerprinting (``detect.yaml``) runs on top.
"""

from __future__ import annotations

import re

from kasauti.shape.model import ShapeFamily
from kasauti.shape.tokens import split_lines

SAMPLE_LINES = 5000
MIN_SCORE = 0.2
_YAML_LINE = re.compile(r"""^(- )?["']?[\w.\-/]+["']?:(\s|$)|^-(\s|$)""")


def score_families(text: str) -> dict[ShapeFamily, float]:
    scores = dict.fromkeys(ShapeFamily, 0.0)
    head = text.lstrip()
    if head.startswith("<"):
        scores[ShapeFamily.XML] = 1.0 if head.rstrip().endswith(">") else 0.6
        return scores
    if head[:1] in ("{", "["):
        scores[ShapeFamily.JSON_YAML] = 1.0
        return scores

    raw = [ln for ln in split_lines(text)[:SAMPLE_LINES] if ln.strip()]
    lines = [ln.strip() for ln in raw if not ln.lstrip().startswith("#")]
    n = max(len(lines), 1)

    starts = [ln.split(None, 1)[0] for ln in lines]
    config = sum(1 for w in starts if w == "config")
    closers = sum(1 for ln in lines if ln in ("next", "end"))
    edits = sum(1 for w in starts if w == "edit")
    if config and closers:
        scores[ShapeFamily.BLOCK_EDIT] = min(1.0, 0.5 + (config + closers + edits) / n)

    menus = sum(1 for ln in lines if re.match(r"^/[a-z]", ln))
    if menus and any("=" in ln for ln in lines):
        scores[ShapeFamily.PATH_COMMAND] = min(1.0, 0.5 + 2 * menus / n)

    sets = sum(1 for w in starts if w in ("set", "delete", "deactivate"))
    scores[ShapeFamily.SET_PATH] = sets / n

    opens = text.count("{")
    closes = text.count("}")
    if opens and abs(opens - closes) <= max(1, opens // 50):
        brace_lines = sum(1 for ln in lines if ln.endswith(("{", "}", ";")))
        scores[ShapeFamily.BRACE] = brace_lines / n

    yaml_lines = sum(1 for ln in raw if _YAML_LINE.match(ln.strip()))
    scores[ShapeFamily.JSON_YAML] = 0.9 * yaml_lines / n

    indented = sum(1 for ln in raw if ln[:1] in (" ", "\t"))
    separators = sum(1 for ln in split_lines(text)[:SAMPLE_LINES] if ln.strip() in ("!", "#"))
    if indented or separators:
        scores[ShapeFamily.INDENT] = min(0.9, 0.3 + (indented + 2 * separators) / n)
    return scores


def detect_family(text: str) -> ShapeFamily:
    scores = score_families(text)
    # ShapeFamily order breaks ties deterministically.
    best = max(scores, key=lambda f: scores[f])
    return best if scores[best] >= MIN_SCORE else ShapeFamily.FLAT
