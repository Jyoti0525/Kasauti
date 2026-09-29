"""Audit and knowledge-base routes for the web UI (PLAN §18.1; TODO M2.76–M2.78, M2.82, M2.83).

    GET /api/audits                     every device audit, newest first, each with a summary
    GET /api/audits?upload={id}         one upload's
    GET /api/jobs/{job}/report.pdf      a device's report (PLAN §15.1)
    GET /api/uploads/{id}/reports.zip   every report of an upload, zipped (R-07)
    GET /api/signing                    who signs the reports: name, source, fingerprint
    GET /api/signing/certificate        the signing certificate (PEM), to trust or verify with
    GET /api/kb                         vendor packs, frameworks and rules installed
    GET /api/kb/vendors/{pack}          one vendor pack's mappings and defaults

A summary is what the dashboard and the results screen show for an audit: its device, its
scores, how many rules failed and how badly. It is worked out from the stored result the first
time it is asked for and kept in memory (a result never changes once written), so the
dashboard doesn't expand every result on every visit. The full result is still
``GET /api/jobs/{job}/result``.

A report is rendered from the stored result when it is asked for, never kept: the PDF holds
the result's masked evidence and nothing else. It is signed with the server's key
(:mod:`kasauti.report.sign`, PLAN §15.3) and names that key in its appendix. The rules it
describes are looked up in the installed knowledge base; a rule removed
since the audit is reported with the result's own words.
"""

from __future__ import annotations

import datetime as dt
import io
import re
import threading
import uuid
import zipfile
from collections import OrderedDict
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool

from kasauti.audit import AuditResult, KnowledgeBase
from kasauti.ingest.store import AuditJob, UploadStore
from kasauti.jobs import Job, JobQueue, JobState
from kasauti.jobs.results import ResultError, decode_result
from kasauti.log import get_logger
from kasauti.report.sign import SigningKey, sign_pdf
from kasauti.rules.scoring import NIST

log = get_logger(__name__)

router = APIRouter(tags=["audits"])

SUMMARY_CACHE = 4096
"""Summaries kept in memory; a few hundred bytes each."""
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
IDENTITY_FIELDS = ("hostname", "vendor", "os_version", "model", "serial", "hardware")
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ScoreOut(_Model):
    framework: str
    title: str
    compliance_pct: float | None
    coverage_pct: float | None
    passed: int
    failed: int
    review: int
    not_applicable: int
    note: str = ""
    benchmarks: tuple[str, ...] = ()


class RuleBrief(_Model):
    rule_id: str
    title: str
    domain: str
    severity: str | None
    """For a failing rule, its worst finding's severity (exposure can raise it above the
    rule's base); otherwise the base."""
    status: str


class Summary(_Model):
    audit_id: str
    hostname: str | None
    vendor: str | None
    pack: str
    os_version: str | None
    model: str | None
    identity_found: int
    """How many of the six identity fields a file (or the user) gave."""
    identity_total: int
    scores: tuple[ScoreOut, ...]
    statuses: dict[str, int]
    """Rules by verdict: PASS, FAIL, REVIEW, N/A."""
    failed_by_severity: dict[str, int]
    rules: tuple[RuleBrief, ...]
    understood_pct: float | None
    """None when the file had no statement to understand."""
    statements: int
    warnings: int


class AuditOut(_Model):
    job_id: str
    upload_id: str
    label: str | None
    name: str
    state: JobState
    error: str | None
    created_at: dt.datetime
    finished_at: dt.datetime | None
    summary: Summary | None
    """For a succeeded audit."""


class _Summaries:
    """Summaries by job id, the oldest dropped past :data:`SUMMARY_CACHE`."""

    def __init__(self) -> None:
        self._kept: OrderedDict[str, Summary] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, job_id: str) -> Summary | None:
        with self._lock:
            found = self._kept.get(job_id)
            if found is not None:
                self._kept.move_to_end(job_id)
            return found

    def put(self, job_id: str, summary: Summary) -> None:
        with self._lock:
            self._kept[job_id] = summary
            while len(self._kept) > SUMMARY_CACHE:
                self._kept.popitem(last=False)


def summarise(result: dict[str, Any]) -> Summary:
    """What the dashboard shows of one audit result (JSON mode, as stored)."""
    identity = result.get("identity", {})

    def value(name: str) -> str | None:
        found = identity.get(name, {}).get("value")
        return None if found is None else str(found)

    # A failing rule counts at its worst finding's severity, which the exposure of the service
    # can raise above the rule's base (Telnet reachable from the internet is critical): the
    # dashboard must say what the findings say.
    worst: dict[str, str] = {}
    for f in result.get("findings", ()):
        sev = f.get("severity")
        if f["status"] == "FAIL" and sev in SEVERITY_RANK:
            known = worst.get(f["rule_id"])
            if known is None or SEVERITY_RANK[sev] < SEVERITY_RANK[known]:
                worst[f["rule_id"]] = sev
    rules = tuple(
        RuleBrief(
            rule_id=r["rule_id"],
            title=r["title"],
            domain=r["domain"],
            severity=worst.get(r["rule_id"], r.get("severity")),
            status=r["status"],
        )
        for r in result.get("rules", ())
    )
    statuses: dict[str, int] = {}
    failed: dict[str, int] = {}
    for r in rules:
        statuses[r.status] = statuses.get(r.status, 0) + 1
        if r.status == "FAIL" and r.severity is not None:
            failed[r.severity] = failed.get(r.severity, 0) + 1
    assurance = result.get("assurance", {})
    return Summary(
        audit_id=result["audit_id"],
        hostname=value("hostname"),
        vendor=value("vendor"),
        pack=result["detection"]["pack_id"],
        os_version=value("os_version"),
        model=value("model"),
        identity_found=sum(value(f) is not None for f in IDENTITY_FIELDS),
        identity_total=len(IDENTITY_FIELDS),
        scores=tuple(
            ScoreOut(
                framework=s["framework"],
                title=s["title"],
                compliance_pct=s.get("compliance_pct"),
                coverage_pct=s.get("coverage_pct"),
                passed=s["passed"],
                failed=s["failed"],
                review=s["review"],
                not_applicable=s["not_applicable"],
                note=s.get("note", ""),
                benchmarks=tuple(s.get("benchmarks", ())),
            )
            for s in result.get("scores", ())
        ),
        statuses=statuses,
        failed_by_severity=failed,
        rules=rules,
        understood_pct=assurance.get("understood_pct"),
        statements=int(assurance.get("statements", 0)),
        warnings=len(result.get("warnings", ())),
    )


# -- routes -----------------------------------------------------------------------------------


@router.get("/api/audits", responses={503: {"description": "database down"}})
async def list_audits(
    request: Request,
    upload: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 500,
) -> tuple[AuditOut, ...]:
    store: UploadStore = request.app.state.uploads
    found: list[AuditJob] = await _db(
        store.audit_jobs, upload_id=None if upload is None else str(upload), limit=limit
    )
    return tuple([await _audit(request, a) for a in found])


@router.get(
    "/api/jobs/{job_id}/report.pdf",
    response_class=Response,
    responses={
        200: {"content": {"application/pdf": {}}, "description": "the report"},
        404: {"description": "no such audit"},
        409: {"description": "the audit has no result (yet)"},
    },
)
async def report(job_id: uuid.UUID, request: Request) -> Response:
    result = await _result(request, str(job_id))
    pdf = await run_in_threadpool(_render, request.app.state.kb, result, request.app.state.signing)
    name = f"{_file_stem(result)}.kasauti.pdf"
    return Response(
        pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@router.get(
    "/api/uploads/{upload_id}/reports.zip",
    response_class=Response,
    responses={
        200: {"content": {"application/zip": {}}, "description": "every report"},
        404: {"description": "no such upload"},
        409: {"description": "no audit of it has succeeded yet"},
    },
)
async def reports(upload_id: uuid.UUID, request: Request) -> Response:
    store: UploadStore = request.app.state.uploads
    found: list[AuditJob] = await _db(store.audit_jobs, upload_id=str(upload_id))
    if not found:
        raise HTTPException(404, "no audit in this upload")
    done = [a for a in found if a.state is JobState.SUCCEEDED]
    if not done:
        raise HTTPException(409, "no audit of this upload has succeeded yet")
    results = [await _result(request, a.job_id) for a in done]
    data = await run_in_threadpool(_zip, request.app.state.kb, results, request.app.state.signing)
    return Response(
        data,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="kasauti-reports.zip"'},
    )


class SigningOut(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    signed: bool
    name: str | None
    source: str | None
    fingerprint: str | None
    """SHA-256 of the certificate (DER), hex: compare it with a report's appendix."""


@router.get("/api/signing")
async def signing(request: Request) -> SigningOut:
    key: SigningKey | None = request.app.state.signing
    if key is None:
        return SigningOut(signed=False, name=None, source=None, fingerprint=None)
    return SigningOut(
        signed=True, name=key.by.name, source=key.by.source, fingerprint=key.by.fingerprint
    )


@router.get(
    "/api/signing/certificate",
    response_class=Response,
    responses={
        200: {"content": {"application/x-pem-file": {}}, "description": "the certificate"},
        404: {"description": "reports are not signed"},
    },
)
async def signing_certificate(request: Request) -> Response:
    key: SigningKey | None = request.app.state.signing
    if key is None:
        raise HTTPException(404, "reports are not signed on this server")
    return Response(
        key.certificate_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="kasauti-signing.pem"'},
    )


# -- knowledge base ---------------------------------------------------------------------------


class VendorOut(_Model):
    id: str
    name: str
    vendor: str
    os_family: str
    shape_family: str
    pack_version: int
    default_role: str | None
    description: str
    mappings: int
    approved: int
    """Mappings a reviewer approved; the others can't be used in an audit."""
    defaults: int
    signatures: int
    learning: bool = False
    """Still being taught in the Training Studio: what it doesn't read stays in review."""


class BenchmarkOut(_Model):
    id: str
    title: str
    version: str
    released: str
    vendors: tuple[str, ...]
    sunset: bool
    source_url: str
    source_sha256: str


class FrameworkOut(_Model):
    id: str
    title: str
    version: str
    source_url: str
    licence: str
    retrieved: str
    controls: int
    benchmarks: tuple[BenchmarkOut, ...] = ()
    bridge: str | None = None
    """The official bridge each control's NIST relation comes from (CCI list, OLIR #155)."""
    mapped_rules: int = 0


class RuleOut(_Model):
    id: str
    title: str
    intent: str
    domain: str
    severity: str
    applies_to: tuple[str, ...]
    for_each: str
    assertion: str
    controls: dict[str, tuple[str, ...]]
    """Framework id to the control ids the rule gives evidence for, on every vendor."""
    vendor_controls: dict[str, dict[str, tuple[str, ...]]] = {}
    """Per-vendor frameworks (DISA STIG): framework id -> vendor pack -> control ids."""
    hardening_best_practice: bool
    fixtures_pass: tuple[str, ...]
    fixtures_fail: tuple[str, ...]


class KbOut(_Model):
    kb_version: str
    ruleset_version: str
    vendors: tuple[VendorOut, ...]
    frameworks: tuple[FrameworkOut, ...]
    rules: tuple[RuleOut, ...]
    control_titles: dict[str, str]
    """Titles of the controls the rules name, in every framework."""


class MappingOut(_Model):
    id: str
    version: int
    match: str
    context: tuple[str, ...]
    entity: str | None
    os_versions: str
    proposed_by: str
    approved_by: tuple[str, ...]
    signals: tuple[str, ...]
    effects: tuple[dict[str, Any], ...]


class DefaultOut(_Model):
    id: str
    attr: str | None
    value: Any
    os_versions: str
    source: str
    reference: str


class VendorDetailOut(_Model):
    vendor: VendorOut
    mappings: tuple[MappingOut, ...]
    defaults: tuple[DefaultOut, ...]


@router.get("/api/kb")
def knowledge_base(request: Request) -> KbOut:
    kb: KnowledgeBase = request.app.state.kb
    titles = {c.id: c.title for f in kb.frameworks.values() for c in f.catalog.controls}
    shared: dict[str, dict[str, list[str]]] = {}
    per_vendor: dict[str, dict[str, dict[str, list[str]]]] = {}
    for f in kb.frameworks.values():
        for e in f.crosswalk.entries if f.crosswalk else ():
            if e.vendor is None:
                shared.setdefault(e.rule, {}).setdefault(f.catalog.framework, []).extend(e.controls)
            else:
                per_vendor.setdefault(e.rule, {}).setdefault(f.catalog.framework, {}).setdefault(
                    e.vendor, []
                ).extend(e.controls)
    rules = tuple(
        RuleOut(
            id=r.id,
            title=r.title,
            intent=r.intent,
            domain=r.domain.value,
            severity=r.severity.base.value,
            applies_to=tuple(role.value for role in r.applies_to),
            for_each=r.for_each,
            assertion=r.assert_,
            controls={
                "nist_800_53r5": tuple(r.refs.nist_800_53r5),
                **{f: tuple(dict.fromkeys(ids)) for f, ids in shared.get(r.id, {}).items()},
            },
            vendor_controls={
                f: {v: tuple(dict.fromkeys(ids)) for v, ids in sorted(by.items())}
                for f, by in per_vendor.get(r.id, {}).items()
            },
            hardening_best_practice=r.hardening_best_practice,
            fixtures_pass=r.fixtures.pass_,
            fixtures_fail=r.fixtures.fail,
        )
        for r in kb.ruleset.rules
    )
    named = {c for r in rules for ids in r.controls.values() for c in ids} | {
        c for r in rules for by in r.vendor_controls.values() for ids in by.values() for c in ids
    }
    return KbOut(
        kb_version=kb.version,
        ruleset_version=kb.ruleset_version,
        vendors=tuple(_vendor(kb, p) for p in sorted(kb.vendor_packs)),
        frameworks=tuple(
            FrameworkOut(
                id=f.catalog.framework,
                title=f.catalog.title,
                version=f.catalog.version,
                source_url=f.catalog.source_url,
                licence=f.catalog.licence,
                retrieved=f.catalog.retrieved,
                controls=len(f.catalog.controls),
                benchmarks=tuple(
                    BenchmarkOut(
                        id=b.id,
                        title=b.title,
                        version=b.version,
                        released=b.released,
                        vendors=b.vendors,
                        sunset=b.sunset,
                        source_url=b.source.url,
                        source_sha256=b.source.sha256,
                    )
                    for b in f.catalog.benchmarks
                ),
                bridge=f.catalog.bridge.title if f.catalog.bridge else None,
                mapped_rules=sum(
                    1
                    for r in rules
                    if r.controls.get(f.catalog.framework)
                    or r.vendor_controls.get(f.catalog.framework)
                ),
            )
            for f in sorted(kb.frameworks.values(), key=lambda f: f.catalog.framework != NIST)
        ),
        rules=rules,
        control_titles={c: titles[c] for c in sorted(named) if c in titles},
    )


@router.get("/api/kb/vendors/{pack_id}", responses={404: {"description": "no such pack"}})
def vendor_pack(pack_id: str, request: Request) -> VendorDetailOut:
    kb: KnowledgeBase = request.app.state.kb
    pack = kb.vendor_packs.get(pack_id)
    if pack is None:
        raise HTTPException(404, "no such vendor pack")
    return VendorDetailOut(
        vendor=_vendor(kb, pack_id),
        mappings=tuple(
            MappingOut(
                id=m.id,
                version=m.provenance.version,
                match=m.match,
                context=m.context,
                entity=None if m.entity is None else m.entity.type,
                os_versions=m.os_versions,
                proposed_by=m.provenance.proposed_by,
                approved_by=m.provenance.approved_by,
                signals=m.provenance.signals,
                effects=tuple(
                    e.model_dump(mode="json", by_alias=True, exclude_defaults=True)
                    for e in m.effects
                ),
            )
            for m in pack.mappings
        ),
        defaults=tuple(
            DefaultOut(
                id=d.id,
                attr=d.attr,
                value=d.value,
                os_versions=d.os_versions,
                source=d.source,
                reference=d.reference,
            )
            for d in pack.defaults.defaults
        ),
    )


# -- helpers ----------------------------------------------------------------------------------


def _vendor(kb: KnowledgeBase, pack_id: str) -> VendorOut:
    pack = kb.vendor_packs[pack_id]
    m = pack.manifest
    return VendorOut(
        id=m.id,
        name=m.name,
        vendor=m.vendor,
        os_family=m.os_family,
        shape_family=m.shape_family,
        pack_version=m.pack_version,
        default_role=None if m.default_role is None else m.default_role.value,
        description=m.description,
        mappings=len(pack.mappings),
        approved=sum(bool(x.provenance.approved_by) for x in pack.mappings),
        defaults=len(pack.defaults.defaults),
        signatures=len(pack.detect.signatures),
        learning=m.learning,
    )


async def _db[T](function: Any, *args: Any, **kwargs: Any) -> T:
    try:
        found: T = await run_in_threadpool(function, *args, **kwargs)
    except SQLAlchemyError as err:
        log.exception("database unavailable", error=str(err))
        raise HTTPException(503, "database unavailable") from None
    return found


async def _audit(request: Request, found: AuditJob) -> AuditOut:
    summary = None
    if found.state is JobState.SUCCEEDED:
        cache: _Summaries = _cache(request)
        summary = cache.get(found.job_id)
        if summary is None:
            try:
                summary = summarise(await _result(request, found.job_id))
            except HTTPException:
                summary = None  # gone since the list was read, or unreadable: shown without
            else:
                cache.put(found.job_id, summary)
    return AuditOut(
        job_id=found.job_id,
        upload_id=found.upload_id,
        label=found.label,
        name=found.name,
        state=found.state,
        error=found.error,
        created_at=found.created_at,
        finished_at=found.finished_at,
        summary=summary,
    )


def _cache(request: Request) -> _Summaries:
    state = request.app.state
    if not hasattr(state, "summaries"):
        state.summaries = _Summaries()
    cache: _Summaries = state.summaries
    return cache


async def _result(request: Request, job_id: str) -> dict[str, Any]:
    """An audit's stored result, expanded (within the result size limit)."""
    queue: JobQueue = request.app.state.jobs
    found: Job | None = await _db(queue.get, job_id)
    if found is None or found.kind != "audit_file":
        raise HTTPException(404, "no such audit")
    blob: bytes | None = await _db(queue.result, job_id) if found.has_result else None
    if blob is None:
        raise HTTPException(409, f"the audit has no result; it is {found.state.value}")
    try:
        result: dict[str, Any] = await run_in_threadpool(decode_result, blob)
    except ResultError as err:
        log.warning("stored result unreadable", job=job_id, error=str(err))
        raise HTTPException(409, "the audit's result can't be read") from None
    return result


def _render(kb: KnowledgeBase, result: dict[str, Any], key: SigningKey | None) -> bytes:
    """The device's report, signed with the server's key (PLAN §15.3)."""
    from kasauti.report.pdf import render_pdf  # noqa: PLC0415 - ReportLab only when needed

    rules = {r.id: r for r in kb.ruleset.rules}
    today = dt.datetime.now(dt.UTC).date().isoformat()
    pdf = render_pdf(
        AuditResult.model_validate(result),
        rules,
        generated=today,
        signed_by=key.by if key else None,
    )
    return sign_pdf(pdf, key) if key else pdf


def _file_stem(result: dict[str, Any]) -> str:
    """A file name for a device's report: its host name, else its file's name; never a path."""
    hostname = result.get("identity", {}).get("hostname", {}).get("value")
    stem = str(hostname or result["input"]["file"].rsplit(".", 1)[0])
    return _SAFE_NAME.sub("_", stem).strip("._")[:80] or "device"


def _zip(kb: KnowledgeBase, results: list[dict[str, Any]], key: SigningKey | None) -> bytes:
    buf = io.BytesIO()
    used: set[str] = set()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for result in results:
            stem = _file_stem(result)
            name, n = f"{stem}.kasauti.pdf", 1
            while name in used:
                n += 1
                name = f"{stem}-{n}.kasauti.pdf"
            used.add(name)
            zf.writestr(name, _render(kb, result, key))
    return buf.getvalue()
