"""The sort job: recognising uploaded files before their upload starts (TODO M2.06).

Runs in a worker process, like an audit (PLAN §5.2: files are parsed only there). For each
file it says what :mod:`kasauti.ingest.devices` needs to find its device: configuration or
command output, which vendor, and the hostname it names. Nothing else leaves the worker: no
line of the file, no serial number.

Unlike an audit, it leaves the staged file where it is, still sealed: the audit reads it
later, and deletes it then (:func:`kasauti.ingest.staging.read_kept`). Only the vendor packs are
loaded, not the rules, and a configuration is parsed only as far as its hostname.

A file it can't read or recognise is reported as ``unknown`` and audited on its own later, so
the user gets that audit's own explanation; recognising never fails an upload. An error
recognising one file makes that file ``unknown``, not the job fail. What no handler can catch
(the worker killed for memory or time, or crashed) fails the job, and the store splits it until
the file that caused it fails alone (:data:`kasauti.ingest.store.SPLIT_WAYS`).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kasauti.identity import companion as companions
from kasauti.identity.detect import Detection, choose, detect_vendor
from kasauti.identity.resolve import companion_value, resolve_identity
from kasauti.ingest.devices import Kind
from kasauti.ingest.model import Artifact
from kasauti.ingest.read import MAX_BYTES, IngestError, decode
from kasauti.ingest.staging import STAGING_KEY_NAME, SealError, is_id, key_id, read_kept
from kasauti.jobs.child import JobError, worker_secret
from kasauti.mapping.setform import parse_config
from kasauti.packs.loader import VendorPack, load_vendor_packs

HOSTNAME_LIMIT = 255
"""Characters of a hostname kept: DNS's limit for a whole name."""


def sort_files(payload: dict[str, Any]) -> dict[str, Any]:
    upload_id = str(payload["upload"])
    ids = [str(i) for i in payload["files"]]
    if not (is_id(upload_id) and all(is_id(i) for i in ids)):
        raise JobError("the job doesn't name uploaded files")
    key = worker_secret(STAGING_KEY_NAME)
    if key is None or key_id(key) != payload.get("staging_key"):
        raise JobError(
            "the uploaded files can't be opened any more: the server restarted since they "
            "were uploaded (its key is kept in memory only); upload them again"
        )
    packs = load_vendor_packs(Path(payload["packs"]))
    vendor = payload.get("vendor")
    staging = Path(payload["staging"])
    out: list[dict[str, Any]] = []
    for file_id in ids:
        try:
            data = _read(staging, key, upload_id, file_id)
        except FileNotFoundError:
            continue  # taken back out of the upload since
        except (SealError, ValueError):
            out.append({"id": file_id, "kind": Kind.UNKNOWN})
            continue
        try:
            found = recognise(data, packs, vendor)
        except Exception:  # one file the parser can't take (too deep, a bug): not the batch's
            found = {"kind": Kind.UNKNOWN}
        out.append({"id": file_id, **found})
        del data
    return {"files": out}


def _read(staging: Path, key: bytes, upload_id: str, file_id: str) -> bytes:
    try:
        return read_kept(staging, key, upload_id, file_id, MAX_BYTES)
    except FileNotFoundError:
        # The job can start between the row's commit and the file's rename, which the store
        # does just after: the file is complete and sealed under either name.
        return read_kept(staging, key, upload_id, file_id, MAX_BYTES, part=True)


def recognise(data: bytes, packs: dict[str, VendorPack], vendor: str | None) -> dict[str, Any]:
    """What one file is, as a JSON object: ``kind``, and ``vendor``, ``command`` and
    ``hostname`` where they apply. With ``vendor`` (chosen for the upload), only that pack
    is tried, as the audit will; otherwise a configuration is recognised first, as the audit
    recognises it, then a command output."""
    try:
        artifact = decode(data, "file")
    except IngestError:
        return {"kind": Kind.UNKNOWN}
    text = artifact.text
    if vendor is not None:
        pack = packs.get(vendor)
        if pack is None:
            return {"kind": Kind.UNKNOWN}
        found = companions.recognise(text, pack)
        if found is not None:
            return _companion(artifact, pack, found)
        return _config(artifact, pack)
    chosen = choose(detect_vendor(text, list(packs.values())))
    if chosen is not None:
        return _config(artifact, packs[chosen.pack_id])
    output = companions.classify(text, list(packs.values()))
    if output is not None:
        return _companion(artifact, *output)
    return {"kind": Kind.UNKNOWN}


def _config(artifact: Artifact, pack: VendorPack) -> dict[str, Any]:
    tree = parse_config(artifact.text, pack, source_file=artifact.name, sha256=artifact.sha256)
    hostname = resolve_identity(tree, pack, None, artifact.text).device.hostname.value
    return {"kind": Kind.CONFIG, "vendor": pack.manifest.id, "hostname": clean_hostname(hostname)}


def _companion(artifact: Artifact, pack: VendorPack, found: Detection) -> dict[str, Any]:
    output = companions.read(artifact, found)
    own = companion_value(output, pack, "hostname")
    return {
        "kind": Kind.COMPANION,
        "vendor": pack.manifest.id,
        "command": output.kind,
        "hostname": clean_hostname(own[0] if own else None),
    }


def clean_hostname(value: object) -> str | None:
    """A hostname fit to store and show: a string of printable characters, at most
    :data:`HOSTNAME_LIMIT` long; None for anything else. The server applies it again to what
    a worker sends back."""
    if not isinstance(value, str):
        return None
    text = "".join(c for c in value if c.isprintable()).strip()
    return text[:HOSTNAME_LIMIT] or None


__all__ = ["HOSTNAME_LIMIT", "clean_hostname", "recognise", "sort_files"]
