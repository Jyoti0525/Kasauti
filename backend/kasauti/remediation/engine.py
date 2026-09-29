"""From failed findings to fixes that are proven by re-auditing them (PLAN §14, R-07c).

One fix per failed check: every entity it fails for (each interface without an access list,
say) is fixed in one change, as an administrator would make it. For each failed finding the
first matching recipe of the vendor pack is filled in from the finding and the configuration
it came from:

* ``{{block}}``: the entity's own block (``line vty 0 4``), from the lines that opened it or its
  facts were read from, never from other evidence such as an exposure elsewhere in the file;
* ``{{key}}`` and ``{{entity}}``: the finding's entity key (``vty 0-4``) and id, and each of the
  entity's known facts by name (``{{privilege}}``);
* ``{{hostname}}``: the device's;
* with ``each``, ``{{line}}``, ``{{block}}``, ``{{inner}}``, ``{{entry}}``, ``{{path}}``,
  ``{{parent}}`` and ``{{above}}`` are each matching statement, its outermost and innermost
  blocks (``config system interface``, ``edit "wan1"``), the nearest PAN-OS ``entry`` name, its
  full path, the path of the block it is in and the path above that, with the pattern's named
  groups and ``with_record``'s fields beside them;
* a line holding ``{{lines}}`` (or ``{{lines_path}}``) is repeated for every statement
  ``lines`` matches;
* ``{{name|drop:a,b}}`` is the value without the words ``a`` and ``b``,
  ``{{name|before:a,b}}`` the words before the first ``a`` or ``b`` (a user's line up to its
  password, keeping its privilege and role), and ``{{name|trim:p}}`` the value without the
  prefix ``p`` (``class:NETADMIN`` → ``NETADMIN``);
* ``each`` and ``lines`` patterns take the same fields, escaped (``^username {{key}} ``).

``<PARAM>`` values stay for the site to fill in. A line ``typed => stored`` is typed one way and
kept another in the configuration (a password typed in clear, kept as a hash). The change, with
each ``<PARAM>`` set to its documentation example, is applied to a copy of the configuration by
the family's editor. Every fix that applies is put on one copy, which is re-audited once: a fix
whose findings no longer fail, with no check worse anywhere, is **verified**. Only a fix that
doesn't settle there is re-audited on its own copy, within :data:`WORK_LIMIT`. Everything shown
has its secrets masked; the rollback is derived from what the change actually altered, or is
the platform's own undo, or is written in the recipe (AWS CLI calls).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field

from kasauti.ingest.mask import MASK, mask_secrets
from kasauti.packs.loader import VendorPack
from kasauti.packs.model import JsonEdit, Recipe, Session
from kasauti.packs.versions import VersionRange
from kasauti.remediation.editors import Applied, Change, EditError, Editor, editor_for
from kasauti.remediation.editors.setpath import set_lines
from kasauti.remediation.model import Fix, FleetFix, Placeholder, Proof, Remediation, Step
from kasauti.rules import regex
from kasauti.rules.model import Finding, Status
from kasauti.shape.model import ConfigTree, ShapeFamily, Statement

_FIELD = re.compile(r"\{\{\s*([a-z_]+)(?:\|(drop|before|trim):([^}]*))?\s*\}\}")
_PARAM = re.compile(r"<([A-Z][A-Z0-9_]*)>")
_ENTITY = re.compile(r"^(\w+)\[(.*)\]$")
_LINES = re.compile(r"\{\{\s*lines(?:_path)?\s*\}\}")
_TOKEN = re.compile(r'"[^"]*"|\S+')
_STATEMENT_FIELDS = frozenset({"line", "block", "inner", "entry", "path", "parent", "above"})
_WHOLE_PARAM = re.compile(r'^"?<[A-Z][A-Z0-9_]*>"?$')
_BAD = (Status.FAIL, Status.REVIEW)
_STORED = re.compile(r"\s+=>(?:\s+|$)")
_CLOSERS = frozenset({"end", "next", "exit"})
DEVICE = "Device[device]"
"""A device-wide finding's entity: shown to people as "this device"."""
_SHOWN_PATHS = 3
WORK_LIMIT = 250_000
"""Statements re-audited, at most, to prove fixes one by one when proving them together didn't
settle every one: a 250-line configuration can have 1,000 fixes checked alone, a 25,000-line
one 10. A count, not a clock, so the same input always gives the same result (PLAN §3.1)."""


class RecipeError(ValueError):
    """A recipe can't be filled in for this finding (a field it names isn't known here)."""


@dataclass(frozen=True)
class Outcome:
    """What an audit said, rule by rule and entity by entity."""

    statuses: dict[tuple[str, str], Status]
    failed: int
    """Failed checks (rules), as the reports count them."""
    compliance_pct: float | None


Reaudit = Callable[[str], Outcome]
"""Audits a changed copy of the configuration's text."""


@dataclass(frozen=True)
class EntityFacts:
    attrs: dict[str, str]
    """Known attributes as text (``privilege`` → ``15``)."""
    lines: tuple[int, ...]
    """The lines that opened the entity, then those its facts were read from."""


def remediate(
    findings: Sequence[Finding],
    *,
    tree: ConfigTree,
    text: str,
    pack: VendorPack,
    device: tuple[str | None, str | None],
    entities: dict[str, EntityFacts],
    original: Outcome,
    reaudit: Reaudit,
) -> Remediation | None:
    """A fix for every failed check in ``findings``. ``device`` is ``(os_version, hostname)``;
    ``entities`` gives what each entity is known by; ``original`` is the audit the findings
    came from."""
    failed = [f for f in findings if f.status is Status.FAIL]
    if not failed:
        return None  # nothing to fix: the result carries no remediation at all
    session = pack.verify.session
    editor = editor_for(pack.manifest.shape_family.value)
    if session is None or editor is None or not pack.recipes:
        why = "this vendor pack has no remediation recipes yet"
        return Remediation(unfixed=tuple(f"{f.rule_id} [{f.entity_id}]: {why}" for f in failed))
    base = _editable_text(tree, text, pack)
    # A brace file edited as `set` lines must read the same both ways, or no proof holds.
    baseline = original if base == text else reaudit(base)
    job = _Job(
        tree=tree,
        pack=pack,
        session=session,
        editor=editor,
        reaudit=reaudit,
        base=base,
        before=baseline,
        os_version=device[0],
        hostname=device[1],
        entities=entities,
        drift=baseline.statuses != original.statuses,
    )
    by_rule: dict[str, list[Finding]] = {}
    for f in failed:
        by_rule.setdefault(f.rule_id, []).append(f)
    for rule_findings in by_rule.values():
        job.prepare(rule_findings)
    job.prove()
    return Remediation(fixes=tuple(job.fixes), unfixed=tuple(job.unfixed), combined=job.fleet)


def _editable_text(tree: ConfigTree, text: str, pack: VendorPack) -> str:
    """Junos brace configurations are edited in their ``display set`` form, which the pack
    reads the same way (checked: a drift between the two readings withholds every proof)."""
    brace = tree.family is ShapeFamily.BRACE and tree.rebuilt_from is None
    if pack.manifest.set_form is not None and brace:
        return set_lines(tree.statements)
    return text


@dataclass
class _Pending:
    """One check's fix, filled in and applied to its own copy, waiting for its proof."""

    findings: list[Finding]
    done: _Rendered
    change: Change
    applied: Applied | None
    why: str = ""
    """Why it couldn't be applied, when ``applied`` is None."""


@dataclass
class _Job:
    tree: ConfigTree
    pack: VendorPack
    session: Session
    editor: Editor
    reaudit: Reaudit
    base: str
    before: Outcome
    os_version: str | None
    hostname: str | None
    drift: bool
    entities: dict[str, EntityFacts]
    fixes: list[Fix] = field(default_factory=list)
    unfixed: list[str] = field(default_factory=list)
    pending: list[_Pending] = field(default_factory=list)
    fleet: FleetFix | None = None

    def __post_init__(self) -> None:
        self.by_line: dict[int, list[Statement]] = {}
        for s in self.tree.statements:  # a `set` file puts several statements on one line
            self.by_line.setdefault(s.line_start, []).append(s)
        self.params = {p.name: p for p in self.pack.verify.params}

    # -- building ------------------------------------------------------------------------------

    def prepare(self, findings: list[Finding]) -> None:
        """One check's fix: each finding filled in from its recipe, all in one change, applied
        to its own copy. A finding no recipe covers is listed as unfixed, with why."""
        done = _Rendered()
        covered: list[Finding] = []
        for f in findings:
            try:
                done.extend(self._render_finding(f))
            except RecipeError as err:
                self.unfixed.append(f"{f.rule_id} [{f.entity_id}]: {err}")
                continue
            covered.append(f)
        if not covered:
            return
        done.lines = _dedupe_chunks(done.lines)
        unknown = sorted({p for t in done.lines for p in _PARAM.findall(t)} - set(self.params))
        if unknown:
            for f in covered:
                self.unfixed.append(
                    f"{f.rule_id} [{f.entity_id}]: the recipe uses {', '.join(unknown)}, which "
                    "its pack doesn't describe"
                )
            return
        change = Change(
            lines=tuple(self._example(_STORED.split(t, maxsplit=1)[0]) for t in done.lines),
            stored=tuple(self._example(_STORED.split(t, maxsplit=1)[-1]) for t in done.lines),
            replaces=tuple(dict.fromkeys(done.replaces)),
            edits=tuple(done.edits),
        )
        try:
            applied = self.editor.apply(self.base, change, self.session)
        except EditError as err:
            why = f"The change couldn't be applied to a copy of this configuration: {err}"
            self.pending.append(_Pending(covered, done, change, None, why))
            return
        self.pending.append(_Pending(covered, done, change, applied))

    def _render_finding(self, f: Finding) -> _Rendered:
        """The first matching recipe that can be filled in for ``f`` (one that finds nothing to
        change here, such as a syslog profile to point at, gives way to the next); recipes
        marked ``combine`` fill in together."""
        candidates = list(_recipes_for(f, self.pack.recipes, self.os_version))
        groups = (
            [[r for r in candidates if r.combine]]
            if candidates and candidates[0].combine
            else [[r] for r in candidates if not r.combine]
        )
        why = RecipeError("no recipe for it on this vendor")
        context = self._context(f)
        evidence = [e.line_start for e in f.evidence]
        for group in groups:
            done = _Rendered()
            for recipe in group:
                try:
                    done.extend(self._render(recipe, context, evidence))
                except RecipeError as err:
                    why = err
            if done.lines:
                return done
        raise why

    # -- proving -------------------------------------------------------------------------------

    def prove(self) -> None:
        """Every fix that applies, applied together to one copy and re-audited once; those that
        didn't settle there, re-audited alone (within :data:`WORK_LIMIT`)."""
        proofs: dict[int, tuple[Proof, str]] = {}
        for p in self.pending:
            if p.applied is None:
                proofs[id(p)] = (Proof.NOT_CHECKED, p.why)
            elif self.drift:
                proofs[id(p)] = (Proof.NOT_CHECKED, _DRIFT)
        ready = [] if self.drift else [p for p in self.pending if p.applied is not None]
        after = self._together(ready)
        if after is not None and not _worse(self.before, after):
            for p in ready:
                if all(after.statuses.get(_target(f)) not in _BAD for f in p.findings):
                    proofs[id(p)] = (Proof.VERIFIED, _together_detail(p.findings, len(ready) - 1))
        alone = WORK_LIMIT // max(1, len(self.tree.statements))
        for p in ready:
            if id(p) in proofs:
                continue
            if alone <= 0:
                proofs[id(p)] = (Proof.NOT_CHECKED, _TOO_BIG)
                continue
            alone -= 1
            text = p.applied.text if p.applied is not None else self.base
            proofs[id(p)] = _judge(p.findings, self.before, self.reaudit(text))
        for p in self.pending:
            proof, detail = proofs[id(p)]
            self.fixes.append(self._fix(p, proof, detail))
        verified = [p for p in ready if proofs[id(p)][0] is Proof.VERIFIED]
        if verified:
            final = after if len(verified) == len(ready) else self._together(verified)
            self.fleet = self._fleet(len(verified), final)

    def _together(self, ready: list[_Pending]) -> Outcome | None:
        """The re-audit of one copy with every fix in ``ready`` applied, or None if they can't
        all be applied to one copy."""
        if not ready:
            return None
        # One script, in order: the same as applying each in turn, with one read and one write
        # of the configuration instead of one per fix.
        merged = Change(
            lines=tuple(line for p in ready for line in p.change.lines),
            stored=tuple(line for p in ready for line in p.change.stored),
            replaces=tuple(dict.fromkeys(r for p in ready for r in p.change.replaces)),
            edits=tuple(e for p in ready for e in p.change.edits),
        )
        try:
            text = self.editor.apply(self.base, merged, self.session).text
        except EditError:
            return None
        return self.reaudit(text)

    def _fleet(self, count: int, after: Outcome | None) -> FleetFix:
        if after is None:
            return FleetFix(
                proof=Proof.NOT_CHECKED,
                detail="The verified fixes couldn't all be applied to one copy together.",
                failed_before=self.before.failed,
                failed_after=self.before.failed,
            )
        worse = _worse(self.before, after)
        still = sorted({r for (r, _), s in after.statuses.items() if s is Status.FAIL})
        failed_before = {r for (r, _), s in self.before.statuses.items() if s is Status.FAIL}
        review = sorted(
            {
                r
                for (r, _), s in after.statuses.items()
                if s is Status.REVIEW and r in failed_before and r not in still
            }
        )
        detail = (
            f"All {count} verified fixes applied together to one copy and re-audited: "
            f"{self.before.failed} failed checks before, {after.failed} after"
        )
        if still:
            detail += f" ({', '.join(still[:5])})"
        if review:
            detail += f"; {len(review)} left for a person to review ({', '.join(review[:5])})"
        detail += "." if not worse else f"; {len(worse)} check(s) got worse together."
        return FleetFix(
            proof=Proof.VERIFIED if not worse else Proof.NOT_VERIFIED,
            detail=detail,
            failed_before=self.before.failed,
            failed_after=after.failed,
            compliance_after_pct=after.compliance_pct,
            still_failing=tuple(still),
            left_for_review=tuple(review),
        )

    # -- the fix as shown ----------------------------------------------------------------------

    def _fix(self, p: _Pending, proof: Proof, detail: str) -> Fix:
        done, applied, change = p.done, p.applied, p.change
        shown = [_STORED.split(t, maxsplit=1)[0] for t in done.lines]
        if done.rollback:
            rollback = tuple(dict.fromkeys(done.rollback))
        elif applied is not None:
            rollback = self._unexample(self.editor.rollback(applied, self.session))
        else:
            rollback = ()
        shown_paths = self._unexample(applied.paths if applied else [])
        paths = _narrowest(_safe_path(q) for q in shown_paths)[:_SHOWN_PATHS]
        if done.check:
            pre = post = list(dict.fromkeys(done.check))
        else:
            pre = [t.replace("{path}", q) for q in paths for t in self.session.precheck]
            post = [t.replace("{path}", q) for q in paths for t in self.session.verify]
        # An export edit isn't something to look for on the device: expect lines only where
        # the change is the configuration's own syntax.
        added = applied.added if applied and not change.edits else []
        expect = [line for _, line in added][:6]
        placeholders = sorted({q for line in shown for q in _PARAM.findall(line)})
        change_shown = _masked([*self.session.enter, *shown, *self.session.exit])
        rollback_shown = _masked(rollback)
        return Fix(
            rule_id=p.findings[0].rule_id,
            entity_ids=tuple(f.entity_id for f in p.findings),
            recipe=" + ".join(f"{self.pack.manifest.id}/{r.id}" for r in done.recipes),
            source=done.recipes[0].source,
            precheck=Step(commands=_masked(dict.fromkeys(pre))),
            change=Step(commands=change_shown, note=_secret_note(sorted(done.used), change_shown)),
            verify=Step(
                commands=_masked(dict.fromkeys(post)),
                note="Expect: " + "; ".join(_masked(self._unexample(expect))) if expect else None,
            ),
            save=Step(commands=self.session.save, note=self.session.save_note)
            if self.session.save or self.session.save_note
            else None,
            rollback=Step(
                commands=rollback_shown, note=_rollback_note(self.session, rollback_shown)
            ),
            placeholders=tuple(
                Placeholder(name=q, means=self.params[q].means) for q in placeholders
            ),
            note=" ".join(dict.fromkeys(r.note for r in done.recipes if r.note)) or None,
            proof=proof,
            proof_detail=detail,
        )

    # -- filling in a recipe -------------------------------------------------------------------

    def _context(self, f: Finding) -> dict[str, str]:
        m = _ENTITY.match(f.entity_id)
        facts = self.entities.get(f.entity_id, EntityFacts({}, ()))
        ctx = {
            **facts.attrs,
            "entity": f.entity_id,
            "key": m.group(2) if m else f.entity_id,
            "hostname": self.hostname or "",
        }
        for n in facts.lines:
            if n in self.by_line:
                s = self.by_line[n][0]
                ctx["block"] = s.path[0] if s.path else s.text
                break
        return ctx

    def _render(
        self, recipe: Recipe, context: dict[str, str], evidence: Sequence[int]
    ) -> _Rendered:
        """The recipe filled in: with ``each``, once per matching statement (a change line that
        names nothing of the statement only once, and an indented line wherever its block's
        line went)."""
        out = _Rendered()
        if recipe.each is None:
            block = context.get("block")
            lines = None if recipe.lines is None else _fill(recipe.lines, context, escape=True)
            for t in recipe.change:
                if not _LINES.search(t):
                    out.lines.append(_fill(t, context))
                    continue
                for s in self.tree.statements:
                    if (
                        lines is not None
                        and regex.search(lines, _full(s))
                        and (block is None or s.path[:1] == (block,))
                    ):
                        out.used.add(s.line_start)
                        out.lines.append(
                            _fill(t, {**context, "lines": s.text, "lines_path": _full(s)})
                        )
            out.add(recipe, context, self._example)
            return out
        each = _fill(recipe.each, context, escape=True)
        pool = self.tree.statements
        if recipe.each_in == "evidence":
            pool = tuple(s for n in dict.fromkeys(evidence) for s in self.by_line.get(n, ()))
        for s in pool:
            found = regex.groups(each, _full(s))
            record = self._record(s, recipe.with_record) if found is not None else None
            if found is None or record is None:
                continue
            ctx = {**context, **_statement_fields(s), **found, **record}
            first, header = not out.used, False
            for t in recipe.change:
                nested = t[:1] == " "
                # A line naming anything the statement gives (its text, a pattern's group, a
                # record's field) is written for every statement.
                own = any(
                    name not in context or name in _STATEMENT_FIELDS
                    for name, _, _ in _FIELD.findall(t)
                )
                keep = first or own or (nested and header)
                if not nested:
                    header = keep
                if keep:
                    out.lines.append(_fill(t, ctx))
            out.add(recipe, ctx, self._example)
            out.used.add(s.line_start)
        if not out.lines:
            raise RecipeError("the recipe found no statement to change")
        return out

    def _record(self, s: Statement, pattern: str | None) -> dict[str, str] | None:
        """``pattern``'s fields from the records beside ``s``'s block; ``{}`` without one."""
        if pattern is None:
            return {}
        for other in self.tree.statements:
            if other.path == s.path[:-1]:
                found = regex.groups(pattern, other.text)
                if found is not None:
                    return found
        return None

    def _example(self, line: str) -> str:
        return _PARAM.sub(lambda m: self.params[m.group(1)].example, line)

    def _unexample(self, lines: Iterable[str]) -> tuple[str, ...]:
        """Lines taken from the verified copy show the site's ``<PARAM>`` again."""
        out = []
        for line in lines:
            for p in self.params.values():
                line = line.replace(p.example, f"<{p.name}>")  # noqa: PLW2901
            out.append(line)
        return tuple(out)


def _recipes_for(f: Finding, recipes: Iterable[Recipe], os_version: str | None) -> Iterator[Recipe]:
    """The recipes for ``f``'s rule and entity on this OS version, in pack order."""
    for r in recipes:
        if r.rule != f.rule_id:
            continue
        if r.entity is not None and not regex.search(r.entity, f.entity_id):
            continue
        scope = VersionRange.parse(r.os_versions)
        if not scope.is_any and (os_version is None or not scope.contains(os_version)):
            continue
        yield r


@dataclass
class _Rendered:
    """Recipes filled in, for one finding or for every finding of one check."""

    lines: list[str] = field(default_factory=list)
    used: set[int] = field(default_factory=set)
    """Configuration lines copied into the change."""
    replaces: list[str] = field(default_factory=list)
    edits: list[JsonEdit] = field(default_factory=list)
    """With their ``<PARAM>`` examples in: edits are applied, never shown."""
    rollback: list[str] = field(default_factory=list)
    check: list[str] = field(default_factory=list)
    recipes: list[Recipe] = field(default_factory=list)

    def add(self, recipe: Recipe, ctx: dict[str, str], example: Callable[[str], str]) -> None:
        """What one filling-in of ``recipe`` adds beside its change lines."""
        self.replaces += [_fill(r, ctx) for r in recipe.replaces]
        self.edits += [_fill_edit(e, ctx, example) for e in recipe.edits]
        self.rollback += [_fill(r, ctx) for r in recipe.rollback]
        self.check += [_fill(c, ctx) for c in recipe.check]
        if recipe not in self.recipes:
            self.recipes.append(recipe)

    def extend(self, other: _Rendered) -> None:
        self.lines += other.lines
        self.used |= other.used
        self.replaces += other.replaces
        self.edits += other.edits
        self.rollback += other.rollback
        self.check += other.check
        self.recipes += [r for r in other.recipes if r not in self.recipes]


def _dedupe_chunks(lines: list[str]) -> list[str]:
    """Leave out a repeated unit: a top-level line with the indented lines and closers
    (``next``, ``end``, ``exit``) after it. Two vty lines' fixes each define the same access
    list; it is typed once."""
    chunks: list[list[str]] = []
    for line in lines:
        word = line.strip().split(" ", 1)[0]
        if chunks and (line[:1] in (" ", "\t") or word in _CLOSERS):
            chunks[-1].append(line)
        else:
            chunks.append([line])
    seen: set[tuple[str, ...]] = set()
    out: list[str] = []
    for chunk in chunks:
        key = tuple(chunk)
        if key in seen:
            continue
        seen.add(key)
        out += chunk
    return out


def _statement_fields(s: Statement) -> dict[str, str]:
    return {
        "line": s.text,
        "block": s.path[0] if s.path else s.text,
        "path": _full(s),
        "parent": " ".join(s.path),
        "above": " ".join(s.path[:-1]),
        "inner": s.path[-1] if s.path else s.text,
        "entry": _entry(s),
    }


def _fill_edit(edit: JsonEdit, ctx: dict[str, str], example: Callable[[str], str]) -> JsonEdit:
    """An export edit with its fields and site values filled in, strings of digits as numbers
    (an AWS port is a number in the export)."""

    def sub(v: object) -> object:
        if isinstance(v, str):
            text = example(_fill(v, ctx))
            return int(text) if text.isdigit() else text
        if isinstance(v, dict):
            return {k: sub(x) for k, x in v.items()}
        if isinstance(v, list):
            return [sub(x) for x in v]
        return v

    return edit.model_copy(
        update={
            "at": example(_fill(edit.at, ctx)),
            "where": {k: sub(v) for k, v in edit.where.items()},
            "value": sub(edit.value),
        }
    )


def _entry(s: Statement) -> str:
    """The name of the nearest ``entry`` a statement is (or is in): a PAN-OS rule or profile."""
    for part in reversed((*s.path, s.text)):
        if part.startswith("entry "):
            return part[6:]
    return ""


def _narrowest(paths: Iterable[str]) -> list[str]:
    """Each path once, leaving out one that another shown path lies under."""
    unique = list(dict.fromkeys(paths))
    return [p for p in unique if not any(q != p and q.startswith(p + " ") for q in unique)]


def _safe_path(path: str) -> str:
    """A path to show, cut before any secret in it and the keyword that names it: ``snmp
    community public`` shows as ``snmp``, so neither the secret nor a masked ``|`` after a
    trailing keyword reaches the pre-check."""
    words, masked = path.split(), mask_secrets(path).split()
    for i, word in enumerate(masked):
        if MASK in word:
            return " ".join(words[: max(1, i - 1)])
    if len(words) > 1 and mask_secrets(f"{path} x").endswith(MASK):
        return " ".join(words[:-1])  # ends in a keyword that names a secret
    return path


def _full(s: Statement) -> str:
    """A statement with the blocks it is in: ``snmp community public``."""
    return " ".join((*s.path, s.text))


def _fill(template: str, ctx: dict[str, str], *, escape: bool = False) -> str:
    """``template`` with its fields filled from ``ctx``; ``escape`` for an RE2 pattern."""

    def one(m: re.Match[str]) -> str:
        name, how, words = m.group(1), m.group(2), m.group(3)
        if name not in ctx:
            raise RecipeError(f"the recipe needs {{{{{name}}}}}, which this finding doesn't give")
        value = ctx[name]
        if how:
            listed = {w.strip() for w in words.split(",")}
            parts = value.split()
            if how == "drop":
                value = " ".join(w for w in parts if w not in listed)
            elif how == "trim":
                value = value.removeprefix(words.strip()).strip()
            else:
                cut = next((i for i, w in enumerate(parts) if w in listed), len(parts))
                value = " ".join(parts[:cut])
        return re.escape(value) if escape else value

    return _FIELD.sub(one, template)


def _masked(lines: Iterable[str]) -> tuple[str, ...]:
    """Every line with its secrets hidden, read in its block as the masker needs: an indented
    line under the last top-level one, a FortiOS line under its ``config``/``edit`` blocks."""
    out: list[str] = []
    top = ""
    stack: list[str] = []
    for line in lines:
        text = line.strip()
        word = text.split(" ", 1)[0]
        nested = line[:1] in (" ", "\t")
        if not nested:
            top = text
        path = list(stack) or ([top] if nested else [])
        out.append(_mask(line.rstrip(), path) if text else line)
        if word in ("config", "edit"):
            stack.append(text)
        elif word in ("next", "end") and stack:
            stack.pop()
    return tuple(out)


def _mask(line: str, path: list[str]) -> str:
    """Secrets masked, but a ``<PARAM>`` the site fills in stays readable even where it stands
    in a secret's place (``key <TACACS_KEY>``): it's a name for a value, not the value."""
    masked = mask_secrets(line, path)
    if "<" not in line or masked == line:
        return masked
    ours = _TOKEN.findall(line)
    spans = list(_TOKEN.finditer(masked))
    if len(ours) != len(spans):
        return masked
    out, pos = [], 0
    for word, m in zip(ours, spans, strict=True):
        out.append(masked[pos : m.start()])
        out.append(word if _WHOLE_PARAM.match(word) else m.group())
        pos = m.end()
    out.append(masked[pos:])
    return "".join(out)


def _secret_note(lines: Sequence[int], shown: Sequence[str]) -> str | None:
    if not lines or not any(MASK in c for c in shown):
        return None
    where = ", ".join(str(n) for n in lines[:6])
    return (
        f"{MASK} hides a secret copied from the configuration (line {where}): type the value "
        "the device's own configuration holds."
    )


def _rollback_note(session: Session, shown: Sequence[str]) -> str:
    if session.rollback:
        return "The platform's own undo: the configuration as it was before this change."
    note = "Puts back what the change altered."
    if any(MASK in c for c in shown):
        note += f" {MASK} is the secret the device had before, as its configuration holds it."
    return note


_DRIFT = (
    "Not re-audited: this configuration reads differently once rewritten for editing, so a "
    "re-audit couldn't be trusted."
)
_TOO_BIG = (
    "Not re-audited on its own: it didn't settle when applied together with the other fixes, "
    "and this configuration is too large to re-audit every fix separately."
)


def _target(f: Finding) -> tuple[str, str]:
    return (f.rule_id, f.entity_id)


def _worse(before: Outcome, after: Outcome, targets: Iterable[tuple[str, str]] = ()) -> list[str]:
    """Checks that fail or wait for review after, and didn't before (``targets`` aside)."""
    skip = set(targets)
    return sorted(
        f"{rule} [{entity}]"
        for (rule, entity), status in after.statuses.items()
        if status in _BAD
        and (rule, entity) not in skip
        and before.statuses.get((rule, entity)) not in _BAD
    )


def _entities(findings: Sequence[Finding]) -> str:
    if len(findings) == 1:
        return "this device" if findings[0].entity_id == DEVICE else findings[0].entity_id
    return f"all {len(findings)} of {', '.join(f.entity_id for f in findings[:3])}" + (
        ", …" if len(findings) > 3 else ""
    )


def _together_detail(findings: Sequence[Finding], others: int) -> str:
    together = f"together with the other {others} fixes " if others else ""
    return (
        f"Applied {together}to a copy of this configuration and re-audited: "
        f"{findings[0].rule_id} no longer fails for {_entities(findings)}, and no other check "
        "got worse."
    )


def _judge(findings: Sequence[Finding], before: Outcome, after: Outcome) -> tuple[Proof, str]:
    """A fix re-audited on its own copy."""
    rule = findings[0].rule_id
    still = [f for f in findings if after.statuses.get(_target(f)) in _BAD]
    worse = _worse(before, after, [_target(f) for f in findings])
    if still:
        return Proof.NOT_VERIFIED, (
            f"Applied to a copy and re-audited: {rule} still fails for {_entities(still)}."
        )
    if worse:
        return Proof.NOT_VERIFIED, (
            f"Applied to a copy and re-audited: the finding is fixed, but {', '.join(worse[:4])} "
            "got worse."
        )
    return Proof.VERIFIED, (
        f"Applied on its own to a copy of this configuration and re-audited: {rule} no longer "
        f"fails for {_entities(findings)}, and no other check got worse."
    )


__all__ = ["WORK_LIMIT", "EntityFacts", "Outcome", "Reaudit", "RecipeError", "remediate"]
