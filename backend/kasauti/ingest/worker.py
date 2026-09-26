"""The audit job: one uploaded file, audited in a worker process (TODO M2.04).

Runs in a fresh process (:mod:`kasauti.jobs.pool`). It reads the staged file and deletes it
before parsing anything, then decodes, audits and returns the result: the same
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
from kasauti.ingest.model import Artifact
from kasauti.ingest.read import MAX_BYTES, IngestError, decode
from kasauti.ingest.staging import is_id, read_once
from kasauti.jobs.pool import JobError


def audit_file(payload: dict[str, Any]) -> dict[str, Any]:
    upload_id, file_id = str(payload["upload"]), str(payload["file"])
    if not (is_id(upload_id) and is_id(file_id)):
        raise JobError("the job doesn't name an uploaded file")
    name = str(payload["name"])
    try:
        data = read_once(Path(payload["staging"]), upload_id, file_id, MAX_BYTES)
    except FileNotFoundError:
        raise JobError(f"{name}: the uploaded file is no longer here; upload it again") from None
    try:
        artifact = decode(data, name)
        del data
        kb = load_kb(Path(payload["packs"]))
        result = audit(
            artifact, kb, vendor=payload.get("vendor"), frameworks=tuple(payload["frameworks"])
        )
    except AuditError as err:
        raise JobError(_companion_message(artifact, kb) or str(err)) from None
    except IngestError as err:
        raise JobError(str(err)) from None
    # JSON-mode data, exactly what the canonical file holds; the pool compresses it as it
    # writes it, so the whole JSON text is never built (kasauti.jobs.results).
    return result.model_dump(mode="json")


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
        "audit (kasauti audit <config> --companion <file>)"
    )
