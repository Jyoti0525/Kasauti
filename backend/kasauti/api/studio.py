"""The Training Studio API (PLAN §11; TODO M2.62-M2.68, M3.23, M3.24).

    GET    /api/studio                               vendor packs, the working set
    POST   /api/studio/files?vendor=                 add a configuration to learn from
    DELETE /api/studio/files/{id}                    remove it
    POST   /api/studio/files/{id}/audit              open it as a new audit (a normal upload)
    GET    /api/studio/meanings                      what a line can mean
    GET    /api/studio/packs/{pack}/queue            patterns the pack doesn't read yet
    POST   /api/studio/ignore                        not security-relevant: leave it out
    POST   /api/studio/proposals                     render, validate and preview a mapping
    GET    /api/studio/proposals                     those waiting for a decision, oldest first
    POST   /api/studio/proposals/{id}/approve        store it; the next audit reads it
    POST   /api/studio/proposals/{id}/reject
    GET    /api/studio/packs/{pack}/taught           mappings taught so far
    DELETE /api/studio/packs/{pack}/taught/{id}      take one back out
    GET    /api/studio/decisions                     who proposed, approved, ignored what

Who proposes, approves or ignores is the signed-in account (:mod:`kasauti.api.auth`); changing
anything here needs the trainer role. A file is sent like an upload's (raw body, name in
``X-File-Name``). It stays in this server's memory only (:mod:`kasauti.studio.workspace`).
After an approval the knowledge base is reloaded in place: the server keeps running (R-03) and
every audit queued from then on reads the new mapping, because each audit loads the packs and
the taught mappings when it starts.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from kasauti.accounts import Account
from kasauti.api.auth import signed_in
from kasauti.audit import KnowledgeBase, audit, load_kb
from kasauti.ingest.read import IngestError, decode
from kasauti.ingest.store import UploadStore
from kasauti.ingest.upload import Received, display_name, inspect, new_id
from kasauti.packs.loader import PackError
from kasauti.rules.scoring import NIST
from kasauti.studio.meanings import Many, TeachError, Token, as_yaml, load_meanings
from kasauti.studio.workspace import (
    MAX_BYTES,
    Impact,
    Pattern,
    Proposal,
    Studio,
    StudioError,
    block_mapping,
    coverage,
)

router = APIRouter(prefix="/api/studio", tags=["studio"])
Signed = Annotated[Account, Depends(signed_in)]
BODY_TYPE = "application/octet-stream"
FILE_NAME_HEADER = "X-File-Name"


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Tally(_Model):
    understood: int
    statements: int
    passed: int
    failed: int
    review: int
    not_applicable: int


class PackOut(_Model):
    id: str
    name: str
    learning: bool
    mappings: int
    taught: int
    files: int
    tally: Tally | None
    """Over the pack's files in the working set, as audited now."""


class FileOut(_Model):
    id: str
    name: str
    pack: str
    added: str
    tally: Tally


class StudioOut(_Model):
    packs: tuple[PackOut, ...]
    files: tuple[FileOut, ...]
    kb_version: str


class ExampleOut(_Model):
    file: str
    line: int
    text: str
    block: str | None


class SuggestionOut(_Model):
    meaning: str
    label: str
    score: float
    why: str
    choices: dict[str, Any]
    roles: dict[int, str]
    signals: tuple[str, ...]


class TokenOut(_Model):
    text: str
    slot: str | None


class PatternOut(_Model):
    key: str
    pattern: str
    block: str | None
    block_taught: bool
    count: int
    files: int
    examples: tuple[ExampleOut, ...]
    tokens: tuple[TokenOut, ...]
    relevance: float
    suggestions: tuple[SuggestionOut, ...]


class RoleOut(_Model):
    name: str
    label: str
    types: tuple[str, ...]
    optional: bool


class ChoiceOut(_Model):
    name: str
    options: tuple[str, ...]
    many: bool


class MeaningOut(_Model):
    id: str
    label: str
    explain: str
    under: str | None
    roles: tuple[RoleOut, ...]
    choices: tuple[ChoiceOut, ...]


class TokenIn(_Model):
    text: str = Field(min_length=1, max_length=512)
    slot: str | None = None
    role: str | None = None


class ProposalIn(_Model):
    pack: str
    key: str
    meaning: str
    tokens: tuple[TokenIn, ...] = Field(min_length=1, max_length=64)
    choices: dict[str, str | list[str]] = Field(default_factory=dict)


class IgnoreIn(_Model):
    pack: str
    key: str


class FlipOut(_Model):
    rule: str
    title: str
    file: str
    before: str
    after: str


class ImpactOut(_Model):
    lines: int
    files: int
    facts: int
    understood_before: int
    understood_after: int
    statements: int
    to_pass: int
    flips: tuple[FlipOut, ...]


class ProposalOut(_Model):
    id: str
    pack: str
    pattern: str
    meaning: str
    mapping_id: str
    mapping: str
    """As the pack will store it (YAML)."""
    impact: ImpactOut
    proposed_by: str
    needs_second: bool


class TaughtOut(_Model):
    id: str
    match: str
    context: tuple[str, ...]
    proposed_by: str
    approved_by: tuple[str, ...]
    mapping: str


class ApprovedOut(_Model):
    mapping_id: str
    kb_version: str


class OpenedOut(_Model):
    upload_id: str


# --- plumbing -----------------------------------------------------------------------------------


def _studio(request: Request) -> Studio:
    studio: Studio = request.app.state.studio
    return studio


def _kb(request: Request) -> KnowledgeBase:
    kb: KnowledgeBase = request.app.state.kb
    return kb


async def _do(fn: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return await run_in_threadpool(fn, *args, **kwargs)
    except (StudioError, TeachError) as err:
        raise HTTPException(409, str(err)) from None


def _reload(request: Request) -> KnowledgeBase:
    """The knowledge base again, with what was just taught. The process keeps running."""
    try:
        kb = load_kb(request.app.state.packs, _studio(request).learned)
    except PackError as err:  # a taught file that no longer loads must never be half-applied
        raise HTTPException(500, "; ".join(err.problems)) from None
    request.app.state.kb = kb
    return kb


def _tally(result: Any) -> Tally:
    c = coverage(result)
    return Tally(
        understood=c["understood"],
        statements=c["statements"],
        passed=c["pass"],
        failed=c["fail"],
        review=c["review"],
        not_applicable=c["na"],
    )


def _state(request: Request) -> StudioOut:
    kb, studio = _kb(request), _studio(request)
    files: list[FileOut] = []
    per_pack: dict[str, list[Tally]] = {}
    for f in sorted(studio.files.values(), key=lambda x: x.added):
        tally = _tally(audit(f.artifact, kb, vendor=f.pack, frameworks=(NIST,), fixes=False))
        per_pack.setdefault(f.pack, []).append(tally)
        files.append(FileOut(id=f.id, name=f.name, pack=f.pack, added=f.added, tally=tally))
    packs = []
    for pid, pack in sorted(kb.vendor_packs.items()):
        tallies = per_pack.get(pid, [])
        packs.append(
            PackOut(
                id=pid,
                name=pack.manifest.name,
                learning=pack.manifest.learning,
                mappings=len(pack.mappings),
                taught=len(studio.taught(pid)),
                files=len(tallies),
                tally=Tally(**{k: sum(getattr(t, k) for t in tallies) for k in Tally.model_fields})
                if tallies
                else None,
            )
        )
    return StudioOut(
        packs=tuple(packs),
        files=tuple(files),
        kb_version=kb.version,
    )


def _pattern(p: Pattern, taught: bool) -> PatternOut:
    return PatternOut(
        key=p.key,
        pattern=p.pattern,
        block=p.block,
        block_taught=taught,
        count=p.count,
        files=p.files,
        examples=tuple(
            ExampleOut(file=e.file, line=e.line, text=e.text, block=e.block) for e in p.examples
        ),
        tokens=tuple(TokenOut(text=t, slot=c[1:-1] if c else None) for t, c in p.tokens),
        relevance=p.relevance,
        suggestions=tuple(
            SuggestionOut(
                meaning=s.meaning,
                label=s.label,
                score=s.score,
                why=s.why,
                choices=s.choices,
                roles=s.roles,
                signals=s.signals,
            )
            for s in p.suggestions
        ),
    )


def _impact(i: Impact) -> ImpactOut:
    return ImpactOut(
        lines=i.lines,
        files=i.files,
        facts=i.facts,
        understood_before=i.understood_before,
        understood_after=i.understood_after,
        statements=i.statements,
        to_pass=i.to_pass,
        flips=tuple(
            FlipOut(rule=f.rule, title=f.title, file=f.file, before=f.before, after=f.after)
            for f in i.flips
        ),
    )


def _proposal(p: Proposal) -> ProposalOut:
    return ProposalOut(
        id=p.id,
        pack=p.pack,
        pattern=p.pattern,
        meaning=p.meaning,
        mapping_id=p.mapping.id,
        mapping=as_yaml(p.mapping),
        impact=_impact(p.impact),
        proposed_by=p.proposed_by,
        needs_second=p.needs_second,
    )


def _pack(request: Request, pack: str) -> None:
    if pack not in _kb(request).vendor_packs:
        raise HTTPException(404, "no such vendor pack")


# --- routes -------------------------------------------------------------------------------------


@router.get("")
async def studio_state(request: Request) -> StudioOut:
    return await run_in_threadpool(_state, request)


@router.post("/files", status_code=201, responses={409: {}, 415: {}, 422: {}})
async def add_file(
    request: Request, vendor: Annotated[str | None, Query(max_length=64)] = None
) -> FileOut:
    media = request.headers.get("content-type", "").partition(";")[0].strip().lower()
    if media != BODY_TYPE:
        raise HTTPException(415, f"send the file's bytes as {BODY_TYPE}")
    given = request.headers.get(FILE_NAME_HEADER)
    if given is None:
        raise HTTPException(422, f"the {FILE_NAME_HEADER} header names the file")
    name = display_name(unquote(given, errors="replace"))
    data = bytearray()
    async for chunk in request.stream():
        data += chunk
        if len(data) > MAX_BYTES:
            raise HTTPException(413, f"{name}: larger than {MAX_BYTES // 1024 // 1024} MiB")
    try:
        artifact = decode(bytes(data), name)
    except IngestError as err:
        raise HTTPException(422, str(err)) from None
    kb = _kb(request)
    f = await _do(_studio(request).add, artifact, kb, vendor)
    result = await run_in_threadpool(
        audit, artifact, kb, vendor=f.pack, frameworks=(NIST,), fixes=False
    )
    return FileOut(id=f.id, name=f.name, pack=f.pack, added=f.added, tally=_tally(result))


@router.delete("/files/{file_id}", status_code=204)
async def remove_file(file_id: str, request: Request) -> Response:
    if not _studio(request).remove(file_id):
        raise HTTPException(404, "no such file in the Studio")
    return Response(status_code=204)


@router.post("/files/{file_id}/audit", status_code=201)
async def open_as_audit(file_id: str, request: Request) -> OpenedOut:
    """The file as a new, ordinary upload (label, frameworks and vendor filled in), ready on the
    New Audit page. Its audit reads everything taught so far."""
    f = _studio(request).files.get(file_id)
    if f is None:
        raise HTTPException(404, "no such file in the Studio")
    store: UploadStore = request.app.state.uploads
    kb = _kb(request)
    data = f.artifact.text.encode("utf-8")

    def stage() -> str:
        uid = store.create(
            label=f"Studio: {f.name}",
            frameworks=sorted(kb.frameworks, key=lambda x: (x != NIST, x)),
            vendor=f.pack,
        )
        fid = new_id()
        sink = store.staging.create(uid, fid)
        try:
            sink.write(data)
        finally:
            sink.close()
        received = Received(fid, f.name, len(data), hashlib.sha256(data).hexdigest())
        store.add(uid, inspect(store.staging, uid, received))
        return uid

    uid = await run_in_threadpool(stage)
    pool = request.app.state.pool  # have the pool recognise it now, not at its next poll
    if pool is not None:
        pool.wake()
    return OpenedOut(upload_id=uid)


@router.get("/meanings")
async def meanings() -> tuple[MeaningOut, ...]:
    return tuple(
        MeaningOut(
            id=m.id,
            label=m.label,
            explain=m.explain,
            under=m.under,
            roles=tuple(
                RoleOut(name=r.name, label=r.label, types=r.types, optional=r.optional)
                for r in m.roles
            ),
            choices=tuple(
                ChoiceOut(
                    name=n,
                    options=o.many if isinstance(o, Many) else o,
                    many=isinstance(o, Many),
                )
                for n, o in m.choose.items()
            ),
        )
        for m in load_meanings().values()
    )


@router.get("/packs/{pack}/queue")
async def queue(pack: str, request: Request) -> tuple[PatternOut, ...]:
    _pack(request, pack)
    kb = _kb(request)
    items = await run_in_threadpool(_studio(request).queue, kb, pack)
    vp = kb.vendor_packs[pack]
    return tuple(_pattern(p, p.block is None or block_mapping(vp, p) is not None) for p in items)


@router.post("/ignore", status_code=204)
async def ignore(body: IgnoreIn, request: Request, who: Signed) -> Response:
    _pack(request, body.pack)
    await _do(_studio(request).ignore, body.pack, body.key, who.username)
    return Response(status_code=204)


@router.post("/proposals", status_code=201)
async def propose(body: ProposalIn, request: Request, who: Signed) -> ProposalOut:
    _pack(request, body.pack)
    tokens = tuple(Token(t.text, t.slot, t.role) for t in body.tokens)  # type: ignore[arg-type]
    choices = {k: tuple(v) if isinstance(v, list) else v for k, v in body.choices.items()}
    p = await _do(
        _studio(request).propose,
        _kb(request),
        pack=body.pack,
        key=body.key,
        meaning=body.meaning,
        tokens=tokens,
        choices=choices,
        by=who.username,
        role=who.role,
    )
    return _proposal(p)


@router.get("/proposals")
async def pending(request: Request) -> tuple[ProposalOut, ...]:
    """Proposals no one has decided yet, whoever made them: a lesson that makes a check pass
    waits here for an approver who signs in later."""
    studio = _studio(request)
    with studio.lock:
        waiting = sorted(studio.proposals.values(), key=lambda p: p.created)
    return tuple(_proposal(p) for p in waiting)


@router.post("/proposals/{proposal_id}/approve")
async def approve(proposal_id: str, request: Request, who: Signed) -> ApprovedOut:
    mapping = await _do(_studio(request).approve, _kb(request), proposal_id, who.username, who.role)
    kb = await run_in_threadpool(_reload, request)
    return ApprovedOut(mapping_id=mapping.id, kb_version=kb.version)


@router.post("/proposals/{proposal_id}/reject", status_code=204)
async def reject(proposal_id: str, request: Request, who: Signed) -> Response:
    await _do(_studio(request).reject, proposal_id, who.username)
    return Response(status_code=204)


@router.get("/packs/{pack}/taught")
async def taught(pack: str, request: Request) -> tuple[TaughtOut, ...]:
    _pack(request, pack)
    return tuple(
        TaughtOut(
            id=m.id,
            match=m.match,
            context=m.context,
            proposed_by=m.provenance.proposed_by,
            approved_by=m.provenance.approved_by,
            mapping=as_yaml(m),
        )
        for m in _studio(request).taught(pack)
    )


@router.delete("/packs/{pack}/taught/{mapping_id:path}", status_code=204)
async def undo(pack: str, mapping_id: str, request: Request, who: Signed) -> Response:
    _pack(request, pack)
    await _do(_studio(request).undo, pack, mapping_id, who.username)
    await run_in_threadpool(_reload, request)
    return Response(status_code=204)


@router.get("/decisions")
async def decisions(request: Request) -> tuple[dict[str, Any], ...]:
    return tuple(reversed(_studio(request).decisions()))


def make_studio(learned: Path, record: Path) -> Studio:
    return Studio(learned=learned, record=record)
