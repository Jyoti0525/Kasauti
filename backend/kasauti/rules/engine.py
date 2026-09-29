"""Rule engine (PLAN §12.1, §12.5, §12.6; TODO M1.10): SBM + rules -> per-entity findings.

For each rule: pick the view (vendor defaults count only for ``on_absent: resolve_default``),
take every entity of the ``for_each`` type that the ``where`` clause keeps, and evaluate the
assertion on it:

=========  ===================================================================
TRUE       PASS
FALSE      FAIL
ABSENT     ``on_absent`` (``resolve_default`` has already been tried: ``on_no_default``)
UNKNOWN    ``on_unknown``
=========  ===================================================================

Then two guards. A PASS or FAIL that rests on a mapping nobody approved becomes REVIEW
(§12.6). A rule with nothing in scope is N/A and says so, unless statements about that
entity type couldn't be read, in which case it's the rule's ``on_unknown`` (usually REVIEW):
an unread vty line must not turn "every vty times out" into N/A.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from functools import cache

from kasauti.packs.loader import RuleSet
from kasauti.rules import expr as ex
from kasauti.rules.enrich import Exposure, adjust_severity
from kasauti.rules.evaluate import (
    TRUE,
    Evaluator,
    Known,
    Missing,
    Observation,
    Val,
    derive,
    evidence_of,
    merge,
)
from kasauti.rules.model import Finding, OnMissing, Rule, Status
from kasauti.sbm.document import SecurityBaselineModel, unread_subject
from kasauti.sbm.entities import Device, Entity
from kasauti.sbm.facts import Evidence, FactState

MAX_ACTUAL = 12
NOTHING_IN_SCOPE = "Not applicable: nothing matches"
"""How a finding begins when the rule found nothing to check, rather than a role it skips."""

_ON_MISSING = {
    OnMissing.RESOLVE_DEFAULT: Status.REVIEW,
    OnMissing.REVIEW: Status.REVIEW,
    OnMissing.FAIL: Status.FAIL,
    OnMissing.NOT_APPLICABLE: Status.NOT_APPLICABLE,
}


def evaluate_rules(sbm: SecurityBaselineModel, ruleset: RuleSet) -> tuple[Finding, ...]:
    """Every rule against one device, rules in id order, entities in key order."""
    derived = {mode: derive(sbm, ruleset.derivations, use_defaults=mode) for mode in (False, True)}
    exposures = {e.id: e for e in ruleset.exposures}
    findings: list[Finding] = []
    for rule in ruleset.rules:
        use_defaults = rule.on_absent is OnMissing.RESOLVE_DEFAULT
        ev = Evaluator(sbm, use_defaults=use_defaults, derived=derived[use_defaults])
        applicable = [exposures[x] for x in rule.exposure if x in exposures]
        findings.extend(_with_exposure(f, applicable, ev) for f in evaluate_rule(rule, sbm, ev))
    return tuple(findings)


def _with_exposure(finding: Finding, exposures: Sequence[Exposure], ev: Evaluator) -> Finding:
    """Adjust the severity of a FAIL or REVIEW by the rule's exposures (PLAN §12.7)."""
    if finding.severity is None or not exposures:
        return finding
    entity = ev.entity(finding.entity_id)
    if entity is None:
        return finding
    severity, reason, evidence = adjust_severity(finding.severity, exposures, ev, entity)

    def key(e: Evidence) -> tuple[str, int, int, str | None]:
        return (e.file, e.line_start, e.line_end, e.mapping_ref)

    def ordered(items: Iterable[Evidence]) -> list[Evidence]:
        return sorted(items, key=lambda e: (e.file, e.line_start, e.mapping_ref or ""))

    # The lines that break the rule come first, then those that only locate it (the WAN
    # interface that raised its severity): a list or report showing one line shows the cause.
    own = {key(e): e for e in finding.evidence}
    where = {key(e): e for e in evidence if key(e) not in own}
    return finding.model_copy(
        update={
            "severity": severity,
            "severity_reason": reason,
            "evidence": (*ordered(own.values()), *ordered(where.values())),
        }
    )


def evaluate_rule(rule: Rule, sbm: SecurityBaselineModel, ev: Evaluator) -> list[Finding]:
    role = sbm.device.role
    if role.state in (FactState.EXPLICIT, FactState.VENDOR_DEFAULT) and role.value not in {
        r.value for r in rule.applies_to
    }:
        return [
            _finding(
                rule,
                sbm.device,
                Status.NOT_APPLICABLE,
                f"Not applicable: the rule covers {', '.join(r.value for r in rule.applies_to)}; "
                f"this device is a {role.value}.",
            )
        ]

    entity_type, where = rule.scope
    assertion = _parse(rule.assert_)
    out: list[Finding] = []
    for entity in ev.members(entity_type):
        in_scope = ev.eval(where, entity) if where is not None else TRUE
        if isinstance(in_scope, Known) and in_scope.value is False:
            continue
        if isinstance(in_scope, Missing):
            out.append(_verdict(rule, entity, in_scope, question="whether it is in scope"))
            continue
        result = ev.eval(assertion, entity)
        out.append(_verdict(rule, entity, result, context=in_scope.why))
    if out:
        return out

    unread = sbm.unread.get(entity_type, ())
    if unread:
        obs = Observation(unread_subject(entity_type, unread), FactState.UNKNOWN, None, unread)
        return [_verdict(rule, sbm.device, Missing("unknown", (obs,)), question="the rule")]
    scope_text = rule.for_each
    return [
        _finding(
            rule,
            sbm.device,
            Status.NOT_APPLICABLE,
            f"{NOTHING_IN_SCOPE} `{scope_text}` on this device.",
        )
    ]


@cache
def _parse(source: str) -> ex.Expr:
    return ex.parse(source)


def _verdict(
    rule: Rule,
    entity: Entity,
    val: Val,
    *,
    context: tuple[Observation, ...] = (),
    question: str | None = None,
) -> Finding:
    # The scope held. A switch it found absent (`not exists(enabled)`: nothing says this
    # source is unused) is the ordinary case on most platforms and would only clutter the
    # finding; absences the verdict itself rests on come from `val.why` and are kept.
    context = tuple(o for o in context if o.state is not FactState.ABSENT)
    why = merge(context, val.why)
    if isinstance(val, Known):
        status = Status.PASS if val.value is True else Status.FAIL
    else:
        handling = rule.on_unknown if val.kind == "unknown" else rule.on_absent
        status = _ON_MISSING[handling]
        if handling is OnMissing.RESOLVE_DEFAULT and rule.on_no_default == "fail":
            status = Status.FAIL

    unapproved = sorted(
        {ref for o in why for e in o.evidence if (ref := e.mapping_ref) and not e.approved_by}
    )
    reason = _reason(rule, entity, status, val, why=why, question=question)
    if unapproved and status in (Status.PASS, Status.FAIL):
        reason = (
            f"Would be {status.value}, but relies on mapping(s) not yet approved: "
            f"{', '.join(str(u) for u in unapproved)}. A second person must approve them "
            f"in the Training Studio."
        )
        status = Status.REVIEW
    return _finding(rule, entity, status, reason, why)


def _finding(
    rule: Rule,
    entity: Entity,
    status: Status,
    reason: str,
    why: tuple[Observation, ...] = (),
) -> Finding:
    judged = status in (Status.FAIL, Status.REVIEW)
    base = rule.severity.base
    evidence = evidence_of((Observation(entity.entity_id, None, None, entity.evidence), *why))
    return Finding(
        rule_id=rule.id,
        entity_id=entity.entity_id,
        status=status,
        severity=base if judged else None,
        severity_reason=f"{base.value.capitalize()} (base)" if judged else None,
        reason=reason,
        actual=_actual(why),
        defaults_used=tuple(sorted({o.default_source for o in why if o.default_source})),
        evidence=evidence,
    )


def _actual(why: Sequence[Observation]) -> tuple[str, ...]:
    lines: list[str] = []
    for o in why:
        if o.state is None and o.value is None:
            continue  # an entity or a missing derived fact: its lines are in the evidence
        if o.value is not None:
            suffix = " (vendor default)" if o.state is FactState.VENDOR_DEFAULT else ""
            lines.append(f"{o.subject} = {o.value}{suffix}")
        elif o.state is FactState.UNKNOWN:
            lines.append(f"{o.subject}: present but not understood")
        else:
            lines.append(f"{o.subject}: missing")
    return tuple(lines[:MAX_ACTUAL])


def _reason(
    rule: Rule,
    entity: Entity,
    status: Status,
    val: Val,
    *,
    why: Sequence[Observation],
    question: str | None,
) -> str:
    who = "the device" if isinstance(entity, Device) else entity.entity_id
    if isinstance(val, Known):
        verdict = "holds" if status is Status.PASS else "is violated"
        defaults = (
            " (using the vendor default for this OS version)"
            if any(o.default_source for o in why)
            else ""
        )
        return f"{rule.title}: {verdict} for {who}{defaults}."
    gaps = [o for o in why if o.state in (FactState.ABSENT, FactState.UNKNOWN)]
    unread = [o.subject for o in gaps if o.state is FactState.UNKNOWN]
    unset = [o.subject for o in gaps if o.state is FactState.ABSENT]
    parts: list[str] = []
    if unread:
        parts.append(f"not understood: {', '.join(unread)}")
    if unset:
        parts.append(f"missing: {', '.join(unset)}")
    detail = "; ".join(parts) or "the facts it needs are missing"
    what = question or "the rule"
    if status is Status.FAIL:
        return f"{rule.title}: fails for {who}; the rule treats absence as a violation ({detail})."
    if status is Status.NOT_APPLICABLE:
        return f"Not applicable to {who} ({detail})."
    no_default = (
        " No vendor default is known for this OS version."
        if val.kind == "absent" and rule.on_absent is OnMissing.RESOLVE_DEFAULT
        else ""
    )
    return f"Cannot judge {what} for {who} ({detail}).{no_default}"
