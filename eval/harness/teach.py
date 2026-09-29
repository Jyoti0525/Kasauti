"""Teaching Huawei VRP in the Training Studio, one approval at a time (PLAN §21.3; TODO M3.28).

A careful trainer, simulated: for each pattern in the Studio's own queue, in the queue's order,
take the top suggestion *if it is the right meaning* (``huawei_truth.yaml``), with the words the
card pre-fills from it, propose it as a trainer and approve it as an approver (four-eyes). A
wrong or missing suggestion counts as one the trainer had to pick by hand; a line no meaning
fits is ignored. After every approval the knowledge base is reloaded, exactly as the server
does, and ``weak.cfg`` is audited: how many of its checks can Kasauti judge now?
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml

from harness.lovo import HUAWEI, HUAWEI_TRUTH, PACKS
from kasauti.accounts.table import Role
from kasauti.audit import KnowledgeBase, load_kb
from kasauti.ingest.read import read_file
from kasauti.rules.model import Status
from kasauti.studio.meanings import Token, load_meanings
from kasauti.studio.workspace import Pattern, Studio, StudioError, _audit, coverage

PACK = "huawei_vrp"


@dataclass(frozen=True, slots=True)
class Step:
    approvals: int
    line: str
    meaning: str
    suggested: bool
    """The top suggestion was the right meaning (the trainer only accepted it)."""
    judged: int
    failed: int
    checks: int
    understood: int
    statements: int


def _tokens(p: Pattern, meaning: str, roles: dict[int, str]) -> tuple[Token, ...]:
    """The card's words as it pre-fills them from a suggestion (frontend Teach.tsx
    ``initialWords``): a value keeps its type; a plain word given a role becomes that role's
    value (the rest of the line, for free text)."""
    m = load_meanings()[meaning]
    out = []
    for i, (text, cls) in enumerate(p.tokens):
        role = roles.get(i)
        types = next((r.types for r in m.roles if r.name == role), ())
        slot = cls[1:-1] if cls else (("LIST" if "LIST" in types else types[0]) if role else None)
        out.append(Token(text, slot, role))  # type: ignore[arg-type]
    return tuple(out)


def _judge(kb: KnowledgeBase) -> tuple[int, int, int, int, int]:
    result = _audit(read_file(HUAWEI / "weak.cfg"), kb, PACK)
    c = coverage(result)
    checks = len([r for r in result.rules if r.status is not Status.NOT_APPLICABLE])
    return c["pass"] + c["fail"], c["fail"], checks, c["understood"], c["statements"]


def run(limit: int = 40) -> tuple[list[Step], list[str]]:
    """Steps (the first is before any approval) and the lines the trainer skipped."""
    truth = {
        (t["pattern"], t["block"]): t["meaning"]
        for t in yaml.safe_load(HUAWEI_TRUTH.read_text(encoding="utf-8"))["lines"]
    }
    skipped: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        learned = Path(tmp) / "learned"
        studio = Studio(learned, Path(tmp) / "record.json")
        kb = load_kb(PACKS, learned)
        for name in ("weak.cfg", "hardened.cfg"):
            studio.add(read_file(HUAWEI / name), kb, PACK)
        steps = [Step(0, "", "", False, *_judge(kb))]
        tried: set[str] = set()
        while len(steps) <= limit:
            queue = [p for p in studio.queue(kb, PACK) if p.key not in tried]
            item = next(
                (p for p in queue if truth.get((p.pattern, p.block or "")) is not None), None
            )
            if item is None:
                break
            tried.add(item.key)
            meaning = truth[(item.pattern, item.block or "")]
            top = item.suggestions[0] if item.suggestions else None
            suggested = top is not None and top.meaning == meaning
            roles = top.roles if suggested and top else {}
            choices = top.choices if suggested and top else {}
            try:
                proposal = studio.propose(
                    kb,
                    pack=PACK,
                    key=item.key,
                    meaning=meaning,
                    tokens=_tokens(item, meaning, roles),
                    choices=choices,
                    by="asha",
                    role=Role.TRAINER,
                )
                studio.approve(kb, proposal.id, "ravi", Role.APPROVER)
            except StudioError as e:
                skipped.append(f"{item.pattern} ({e})")
                continue
            kb = load_kb(PACKS, learned)
            steps.append(Step(len(steps), item.pattern, meaning, suggested, *_judge(kb)))
        skipped += [
            p.pattern
            for p in studio.queue(kb, PACK)
            if truth.get((p.pattern, p.block or "")) is not None and p.key not in tried
        ]
    return steps, skipped


def report(steps: list[Step], skipped: list[str]) -> str:
    first, last = steps[0], steps[-1]
    accepted = sum(s.suggested for s in steps[1:])
    lines = [
        "| Approvals | Line taught | Meaning | Top suggestion right | "
        "Checks judged | Failing | Lines understood |",
        "|---:|---|---|:-:|---:|---:|---:|",
        f"| 0 | (untaught) | | | {first.judged} of {first.checks} | {first.failed} | "
        f"{first.understood} of {first.statements} |",
    ]
    for s in steps[1:]:
        lines.append(
            f"| {s.approvals} | `{s.line}` | {s.meaning} | {'yes' if s.suggested else 'no'} | "
            f"{s.judged} of {s.checks} | {s.failed} | {s.understood} of {s.statements} |"
        )
    lines += [
        "",
        f"After {last.approvals} approvals Kasauti judges **{last.judged} of {last.checks}** "
        f"checks on `weak.cfg` ({last.failed} failing); the top suggestion was the right "
        f"meaning for {accepted} of them.",
    ]
    if skipped:
        lines += ["", "Not taught:", "", *[f"- `{s}`" for s in skipped]]
    return "\n".join(lines)


REPORT = Path(__file__).resolve().parents[1] / "reports" / "huawei_teach.md"


def markdown(steps: list[Step], skipped: list[str]) -> str:
    """``eval/reports/huawei_teach.md``, as committed: a test checks it matches a fresh run."""
    return (
        "# Teaching Huawei VRP in the Training Studio\n\n"
        "Generated by `uv run python -m harness teach` (eval/harness/teach.py); do not edit by "
        "hand. A careful trainer, simulated: each pattern of the Studio's own queue, in order, "
        "taught with the top suggestion when it is the right meaning "
        "(eval/harness/huawei_truth.yaml), proposed by a trainer and approved by an approver; "
        "after every approval `weak.cfg` is audited again.\n\n"
        + report(steps, skipped)
        + "\n\nThe checks still in review rest on lines no Studio meaning can express yet "
        "(local accounts and their password storage, AAA servers and schemes, access-list "
        "entries, login lockout): teaching those needs the free attribute tree (TODO M2.65), "
        "and their Huawei semantics taken from Huawei's documentation, not guessed.\n"
    )
