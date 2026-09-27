"""The audit job: one device of an upload, audited in a worker process (TODO M2.04, M2.06).

Runs in a fresh process (:mod:`kasauti.jobs.pool`, :mod:`kasauti.jobs.child`). It reads the
device's staged files, its configuration and the command outputs paired with it
(:mod:`kasauti.ingest.devices`), which are sealed (:mod:`kasauti.ingest.sealed`); it deletes
each as it reads it, and only then decrypts it in memory. Nothing is parsed until every file is
read and deleted. It decodes, audits and returns the result: the same
:class:`~kasauti.audit.AuditResult` ``kasauti audit`` writes, in which every configuration line
is masked. The knowledge base is loaded from the pack files each time, so an audit always names
the exact packs it used.

Failures the user should read (not a text file, vendor not recognised) are raised as
:class:`~kasauti.jobs.JobError`; their messages name the file, never its content.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kasauti.audit import AuditError, KnowledgeBase, audit, load_kb
from kasauti.identity.companion import COMMANDS, classify
from kasauti.ingest.devices import MAX_COMPANIONS
from kasauti.ingest.model import Artifact
from kasauti.ingest.read import MAX_BYTES, IngestError, decode
from kasauti.ingest.staging import (
    STAGING_KEY_NAME,
    SealError,
    delete_staged,
    is_id,
    key_id,
    read_once,
)
from kasauti.jobs.child import JobError, worker_secret

_UNREADABLE = (
    "the uploaded file can't be opened any more: the server restarted since it was uploaded "
    "(its key is kept in memory only); upload it again"
)


def audit_file(payload: dict[str, Any]) -> dict[str, Any]:
    upload_id, file_id = str(payload["upload"]), str(payload["file"])
    paired = [(str(c["id"]), str(c["name"])) for c in payload.get("companions", ())]
    if not (is_id(upload_id) and is_id(file_id) and all(is_id(i) for i, _ in paired)):
        raise JobError("the job doesn't name uploaded files")
    if len(paired) > MAX_COMPANIONS:
        raise JobError(f"a device takes at most {MAX_COMPANIONS} command outputs")
    name = str(payload["name"])
    staging = Path(payload["staging"])
    key = worker_secret(STAGING_KEY_NAME)
    if key is None or key_id(key) != payload.get("staging_key"):
        # Sealed under a key this process doesn't hold: the server restarted since the upload
        # (keys live in memory only), or another server process queued it.
        for staged in (file_id, *(i for i, _ in paired)):
            delete_staged(staging, upload_id, staged)
        raise JobError(f"{name}: {_UNREADABLE}")
    data = _read(staging, key, upload_id, file_id, name)
    outputs = [(n, _read(staging, key, upload_id, i, n)) for i, n in paired]
    try:
        artifact = decode(data, name)
        del data
        given = [decode(raw, n) for n, raw in outputs]
        del outputs
        kb = load_kb(Path(payload["packs"]))
        result = audit(
            artifact,
            kb,
            vendor=payload.get("vendor"),
            frameworks=tuple(payload["frameworks"]),
            companions=given,
        )
    except AuditError as err:
        raise JobError(_companion_message(artifact, kb) or str(err)) from None
    except IngestError as err:
        raise JobError(str(err)) from None
    # JSON-mode data, exactly what the canonical file holds; the pool compresses it as it
    # writes it, so the whole JSON text is never built (kasauti.jobs.results).
    return result.model_dump(mode="json")


def _read(staging: Path, key: bytes, upload_id: str, file_id: str, name: str) -> bytes:
    """One staged file, read once and deleted (:func:`read_once`)."""
    try:
        return read_once(staging, key, upload_id, file_id, MAX_BYTES)
    except FileNotFoundError:
        raise JobError(f"{name}: the uploaded file is no longer here; upload it again") from None
    except SealError:
        raise JobError(f"{name}: {_UNREADABLE}") from None


def _companion_message(artifact: Artifact, kb: KnowledgeBase) -> str | None:
    """For a file that isn't a configuration but a companion output (TODO M2.05): what it is,
    and how it is used, rather than "can't tell which vendor this is"."""
    found = classify(artifact.text, list(kb.vendor_packs.values()))
    if found is None:
        return None
    pack, detection = found
    return (
        f"{artifact.name}: {COMMANDS[detection.pack_id]} output from a {pack.manifest.name} "
        "device, not a configuration; it adds the serial number and hardware to that device's "
        "audit: upload it with that device's configuration (or kasauti audit <config> "
        "--companion <file>)"
    )
