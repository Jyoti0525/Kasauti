"""Uploads in the database and staging housekeeping (TODO M2.04), on SQLite and PostgreSQL."""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import time
from pathlib import Path

import pytest
from sqlalchemy import Engine, select, update

from kasauti.ingest import store as store_module
from kasauti.ingest.read import MAX_BYTES
from kasauti.ingest.staging import Staging
from kasauti.ingest.store import (
    AUDIT_KIND,
    AUDIT_TIMEOUT_PER_MIB_S,
    AUDIT_TIMEOUT_S,
    OPEN_TTL,
    UploadNotFoundError,
    UploadStateError,
    UploadStore,
    audit_timeout,
)
from kasauti.ingest.table import UploadState
from kasauti.ingest.upload import Received, new_id
from kasauti.jobs import JobQueue, JobState
from kasauti.jobs.queue import utcnow
from kasauti.jobs.table import jobs

PACKS = Path(__file__).resolve().parents[3] / "packs"


@pytest.fixture
def store(any_engine: Engine, tmp_path: Path) -> UploadStore:
    staging = Staging(tmp_path / "staging")
    staging.prepare()
    return UploadStore(any_engine, staging)


@pytest.fixture
def queue(any_engine: Engine) -> JobQueue:
    return JobQueue(any_engine, {AUDIT_KIND})


def _open(store: UploadStore) -> str:
    return store.create(label="t", frameworks=["nist_800_53r5"], vendor=None)


def _staged(store: UploadStore, upload_id: str, data: bytes, name: str = "r.cfg") -> Received:
    file_id = new_id()
    with store.staging.create(upload_id, file_id) as sink:
        sink.write(data)
    return Received(file_id, name, len(data), hashlib.sha256(data).hexdigest())


def test_files_are_recorded_and_committed_to_staging(store: UploadStore) -> None:
    uid = _open(store)
    one, two = _staged(store, uid, b"a\n", "a.cfg"), _staged(store, uid, b"b\n", "b.cfg")
    refused = Received(new_id(), "x.exe", 0, None, "not a configuration file type")
    store.add(uid, [one, two, refused])
    view = store.get(uid)
    assert view is not None
    assert [(f.name, f.accepted, f.reason) for f in view.files] == [
        ("a.cfg", True, None),
        ("b.cfg", True, None),
        ("x.exe", False, "not a configuration file type"),
    ]
    for r in (one, two):
        assert store.staging.path(uid, r.id).exists()
        assert not store.staging.part(uid, r.id).exists()


def test_the_same_content_twice_is_refused_as_a_duplicate(store: UploadStore) -> None:
    uid = _open(store)
    store.add(uid, [_staged(store, uid, b"same\n", "site-a/r.cfg")])
    second = _staged(store, uid, b"same\n", "site-b/r.cfg")
    (row,) = store.add(uid, [second])
    assert row.reason == "the same content as site-a/r.cfg"
    assert not store.staging.part(uid, second.id).exists()
    assert not store.staging.path(uid, second.id).exists()


def test_the_per_upload_limits_hold(store: UploadStore, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(store_module, "MAX_FILES", 2)
    monkeypatch.setattr(store_module, "MAX_UPLOAD_BYTES", 10)
    uid = _open(store)
    rows = store.add(
        uid,
        [
            _staged(store, uid, b"1234\n"),
            _staged(store, uid, b"5678\n"),
            _staged(store, uid, b"9\n"),
        ],
    )
    assert [r.reason for r in rows] == [
        None,
        None,
        "the upload already has 2 files; start another for the rest",
    ]
    uid = _open(store)
    rows = store.add(uid, [_staged(store, uid, b"123456\n"), _staged(store, uid, b"abcdef\n")])
    assert rows[1].reason == "the upload would pass 0 GiB; start another"


def test_an_upload_takes_no_files_once_started_and_starts_once(
    store: UploadStore, queue: JobQueue
) -> None:
    uid = _open(store)
    first = _staged(store, uid, b"hostname R1\n")
    store.add(uid, [first])
    (job_id,) = store.start(uid, queue, packs=PACKS)
    job = queue.get(job_id)
    assert job is not None
    assert (job.kind, job.state) == (AUDIT_KIND, JobState.QUEUED)
    view = store.get(uid)
    assert view is not None
    assert view.state is UploadState.STARTED
    assert view.files[0].job_id == job_id
    late = _staged(store, uid, b"hostname R2\n")
    with pytest.raises(UploadStateError, match="has started"):
        store.add(uid, [late])
    assert not store.staging.part(uid, late.id).exists(), "a refused add deletes its files"
    with pytest.raises(UploadStateError, match="has started"):
        store.start(uid, queue, packs=PACKS)
    with pytest.raises(UploadStateError):
        store.check_open(uid)


def test_the_job_payload_is_references_not_content(store: UploadStore, queue: JobQueue) -> None:
    uid = _open(store)
    store.add(uid, [_staged(store, uid, b"hostname SECRET-HOST\n", "r1.cfg")])
    (job_id,) = store.start(uid, queue, packs=PACKS)
    with store.engine.connect() as conn:
        payload = conn.execute(jobs.select().where(jobs.c.id == job_id)).one().payload
    assert "SECRET-HOST" not in payload
    assert '"name":"r1.cfg"' in payload


def test_nothing_to_start_without_an_accepted_file(store: UploadStore, queue: JobQueue) -> None:
    uid = _open(store)
    store.add(uid, [Received(new_id(), "a.exe", 0, None, "not a configuration file type")])
    with pytest.raises(UploadStateError, match="nothing to audit"):
        store.start(uid, queue, packs=PACKS)
    assert queue.pending() == 0


def test_removing_a_file_and_discarding_an_upload_delete_their_files(store: UploadStore) -> None:
    uid = _open(store)
    one, two = _staged(store, uid, b"1\n"), _staged(store, uid, b"2\n")
    store.add(uid, [one, two])
    assert store.remove_file(uid, one.id)
    assert not store.staging.path(uid, one.id).exists()
    assert not store.remove_file(uid, one.id)
    store.discard(uid)
    assert not (store.staging.root / uid).exists()
    view = store.get(uid)
    assert view is not None
    assert view.state is UploadState.DISCARDED
    with pytest.raises(UploadStateError, match="discarded"):
        store.discard(uid)


def test_unknown_uploads(store: UploadStore) -> None:
    missing = new_id()
    assert store.get(missing) is None
    with pytest.raises(UploadNotFoundError):
        store.check_open(missing)
    with pytest.raises(UploadNotFoundError):
        store.add(missing, [])


def test_an_upload_left_open_expires_and_its_files_go(store: UploadStore) -> None:
    uid = _open(store)
    staged = _staged(store, uid, b"hostname R1\n")
    store.add(uid, [staged])
    assert store.housekeep() == 0
    assert store.staging.path(uid, staged.id).exists()
    assert store.housekeep(now=utcnow() + OPEN_TTL + dt.timedelta(minutes=1)) == 1
    view = store.get(uid)
    assert view is not None
    assert view.state is UploadState.EXPIRED
    assert not (store.staging.root / uid).exists()


def test_housekeeping_keeps_what_a_queued_job_needs_and_deletes_the_rest(
    store: UploadStore, queue: JobQueue
) -> None:
    uid = _open(store)
    waiting = _staged(store, uid, b"1\n", "1-waiting.cfg")
    cancelled = _staged(store, uid, b"2\n", "2-cancelled.cfg")
    store.add(uid, [waiting, cancelled])
    job_waiting, job_cancelled = store.start(uid, queue, packs=PACKS)
    queue.cancel(job_cancelled)  # ended without its worker ever reading the file
    assert store.housekeep() == 1
    assert store.staging.path(uid, waiting.id).exists()
    assert not store.staging.path(uid, cancelled.id).exists()
    with store.engine.begin() as conn:
        conn.execute(update(jobs).where(jobs.c.id == job_waiting).values(state=JobState.FAILED))
    assert store.housekeep() == 1
    assert not (store.staging.root / uid).exists()


def test_housekeeping_clears_orphans_and_stale_parts_but_not_files_in_flight(
    store: UploadStore,
) -> None:
    orphan = new_id()  # a directory no upload row refers to (a crash mid-create)
    with store.staging.create(orphan, new_id()) as sink:
        sink.write(b"x")
    uid = _open(store)
    fresh = _staged(store, uid, b"arriving\n")  # a .part still being received
    stale = _staged(store, uid, b"abandoned\n")
    old = time.time() - OPEN_TTL.total_seconds() - 60
    os.utime(store.staging.part(uid, stale.id), (old, old))
    stranger = store.staging.root / "not-ours"
    stranger.mkdir()
    assert store.housekeep() == 2
    assert not (store.staging.root / orphan).exists()
    assert store.staging.part(uid, fresh.id).exists()
    assert not store.staging.part(uid, stale.id).exists()
    assert stranger.exists(), "housekeeping deletes only what staging creates"


def test_an_audit_s_time_limit_grows_with_its_file(store: UploadStore, queue: JobQueue) -> None:
    assert audit_timeout(0) == AUDIT_TIMEOUT_S
    assert audit_timeout(MAX_BYTES) == AUDIT_TIMEOUT_S + 20 * AUDIT_TIMEOUT_PER_MIB_S
    uid = _open(store)
    small = _staged(store, uid, b"hostname R1\n", "small.cfg")
    large = _staged(store, uid, b"!" * (3 * 1024 * 1024 + 1), "large.cfg")
    store.add(uid, [small, large])
    timeouts = []
    for job_id in store.start(uid, queue, packs=PACKS):
        with store.engine.connect() as conn:
            timeouts.append(
                conn.execute(select(jobs.c.timeout_s).where(jobs.c.id == job_id)).scalar_one()
            )
    # In name order; a part of a second rounds up.
    assert timeouts == [AUDIT_TIMEOUT_S + 3 * AUDIT_TIMEOUT_PER_MIB_S + 1, AUDIT_TIMEOUT_S + 1]
