"""Uploads in the database, devices and staging housekeeping (TODO M2.04, M2.06), on SQLite
and PostgreSQL."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine, select, update

from kasauti.identity.manual import ManualEntryError
from kasauti.ingest import store as store_module
from kasauti.ingest.devices import How, Kind
from kasauti.ingest.read import MAX_BYTES
from kasauti.ingest.sealed import new_key
from kasauti.ingest.sort import HOSTNAME_LIMIT, sort_files
from kasauti.ingest.staging import STAGING_KEY_NAME, Staging
from kasauti.ingest.store import (
    AUDIT_KIND,
    AUDIT_TIMEOUT_PER_MIB_S,
    AUDIT_TIMEOUT_S,
    OPEN_TTL,
    SORT_KIND,
    FileNotInUploadError,
    PairingError,
    Recognition,
    UploadNotFoundError,
    UploadStateError,
    UploadStore,
    UploadView,
    audit_timeout,
)
from kasauti.ingest.table import UploadState
from kasauti.ingest.upload import Received, new_id
from kasauti.jobs import JobQueue, JobState
from kasauti.jobs.child import set_worker_secrets
from kasauti.jobs.queue import utcnow
from kasauti.jobs.results import encode_result
from kasauti.jobs.table import jobs

REPO = Path(__file__).resolve().parents[3]
PACKS = REPO / "packs"
AUTHORED = REPO / "datasets" / "authored"
KEY = new_key()


@pytest.fixture(autouse=True)
def _worker_secrets() -> Iterator[None]:
    """Sort jobs run in this process here (:func:`_recognise`), with the key a pool hands a
    worker."""
    set_worker_secrets({STAGING_KEY_NAME: KEY})
    yield
    set_worker_secrets({})


@pytest.fixture
def queue(any_engine: Engine) -> JobQueue:
    return JobQueue(any_engine, {AUDIT_KIND, SORT_KIND})


@pytest.fixture
def store(any_engine: Engine, tmp_path: Path, queue: JobQueue) -> UploadStore:
    staging = Staging(tmp_path / "staging", KEY)
    staging.prepare()
    return UploadStore(any_engine, staging, queue, PACKS)


def _recognise(store: UploadStore) -> None:
    """Run every queued sort job, in this process, as a worker would."""
    sorter = JobQueue(store.engine, {SORT_KIND})
    for claim in sorter.claim("test", 100):
        result = encode_result(sort_files(json.loads(claim.payload)))
        assert sorter.finish("test", claim.id, JobState.SUCCEEDED, result=result)


def _view(store: UploadStore, upload_id: str) -> UploadView:
    view = store.get(upload_id)
    assert view is not None
    return view


def _sample(vendor: str, name: str) -> bytes:
    folder = AUTHORED / vendor
    path = folder / name if (folder / name).exists() else folder / "companions" / name
    return path.read_bytes()


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
    _recognise(store)
    (job_id,) = store.start(uid)
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
        store.start(uid)
    with pytest.raises(UploadStateError):
        store.check_open(uid)


def test_the_job_payload_is_references_not_content(store: UploadStore, queue: JobQueue) -> None:
    uid = _open(store)
    store.add(uid, [_staged(store, uid, b"hostname SECRET-HOST\n", "r1.cfg")])
    _recognise(store)
    (job_id,) = store.start(uid)
    with store.engine.connect() as conn:
        payloads = [p for (p,) in conn.execute(select(jobs.c.payload))]
        audit = conn.execute(select(jobs.c.payload).where(jobs.c.id == job_id)).scalar_one()
    assert len(payloads) == 2, "the sort job and the audit"
    assert not any("SECRET-HOST" in p for p in payloads)
    assert '"name":"r1.cfg"' in audit


def test_nothing_to_start_without_an_accepted_file(store: UploadStore, queue: JobQueue) -> None:
    uid = _open(store)
    store.add(uid, [Received(new_id(), "a.exe", 0, None, "not a configuration file type")])
    with pytest.raises(UploadStateError, match="nothing to audit"):
        store.start(uid)
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
    _recognise(store)
    job_waiting, job_cancelled = store.start(uid)
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
    _recognise(store)
    timeouts = []
    for job_id in store.start(uid):
        with store.engine.connect() as conn:
            timeouts.append(
                conn.execute(select(jobs.c.timeout_s).where(jobs.c.id == job_id)).scalar_one()
            )
    # In name order; a part of a second rounds up.
    assert timeouts == [AUDIT_TIMEOUT_S + 3 * AUDIT_TIMEOUT_PER_MIB_S + 1, AUDIT_TIMEOUT_S + 1]


# -- devices (TODO M2.06) ---------------------------------------------------------------------


def _sort_job(store: UploadStore, file_id: str) -> str | None:
    with store.engine.connect() as conn:
        found: str | None = conn.execute(
            select(store_module.upload_files.c.sort_job_id).where(
                store_module.upload_files.c.id == file_id
            )
        ).scalar_one()
    return found


def test_files_join_the_sort_job_still_queued_and_start_waits_for_it(
    store: UploadStore, queue: JobQueue
) -> None:
    uid = _open(store)
    a = _staged(store, uid, b"hostname A\n", "a.cfg")
    store.add(uid, [a])
    b = _staged(store, uid, b"x" * (2 * 1024 * 1024), "b.cfg")
    store.add(uid, [b])
    job = _sort_job(store, a.id)
    assert job is not None
    assert _sort_job(store, b.id) == job, "one job for both"
    with store.engine.connect() as conn:
        row = conn.execute(select(jobs).where(jobs.c.id == job)).one()
    assert json.loads(row.payload)["files"] == [a.id, b.id]
    assert row.timeout_s == audit_timeout(a.size + b.size)
    assert [f.recognition for f in _view(store, uid).files] == [Recognition.PENDING] * 2
    assert _view(store, uid).recognising == 2
    with pytest.raises(UploadStateError, match="2 files are still being recognised"):
        store.start(uid)
    assert _view(store, uid).state is UploadState.OPEN

    (claimed,) = JobQueue(store.engine, {SORT_KIND}).claim("elsewhere", 1)  # now running
    c = _staged(store, uid, b"hostname C\n", "c.cfg")
    store.add(uid, [c])
    assert _sort_job(store, c.id) not in (None, job), "a running job takes no more"
    assert claimed.id == job


def test_a_removed_file_drops_out_of_the_queued_sort_job(store: UploadStore) -> None:
    uid = _open(store)
    a, b = _staged(store, uid, b"a\n", "a.cfg"), _staged(store, uid, b"b\n", "b.cfg")
    store.add(uid, [a, b])
    store.remove_file(uid, a.id)
    c = _staged(store, uid, b"c\n", "c.cfg")
    store.add(uid, [c])
    job = _sort_job(store, c.id)
    with store.engine.connect() as conn:
        payload = json.loads(conn.execute(select(jobs.c.payload).where(jobs.c.id == job)).one()[0])
    assert payload["files"] == [b.id, c.id]


def test_devices_are_found_and_each_is_audited_with_its_outputs(
    store: UploadStore, queue: JobQueue
) -> None:
    uid = _open(store)
    files = {
        "EDGE-R1.cfg": _sample("cisco_ios_xe", "hardened.cfg"),
        "show_version.txt": _sample("cisco_ios_xe", "show_version.txt"),  # names EDGE-R1
        "edge-r1_show_inventory.txt": _sample("cisco_ios_xe", "show_inventory.txt"),
        "leaf1/running.cfg": _sample("arista_eos", "hardened.cfg"),  # host LEAF-1
        "leaf1/show_version.txt": _sample("arista_eos", "show_version.txt"),  # names no host
    }
    staged = {name: _staged(store, uid, data, name) for name, data in files.items()}
    store.add(uid, list(staged.values()))
    assert store.staging.path(uid, staged["EDGE-R1.cfg"].id).exists()
    _recognise(store)
    ids = {name: r.id for name, r in staged.items()}
    view = _view(store, uid)
    assert view.recognising == 0
    assert all(p.is_file() for p in (store.staging.root / uid).iterdir()), "recognising keeps them"
    by_name = {f.name: f for f in view.files}
    assert by_name["EDGE-R1.cfg"].recognised is not None
    assert (by_name["EDGE-R1.cfg"].recognised.kind, by_name["EDGE-R1.cfg"].recognised.hostname) == (
        Kind.CONFIG,
        "EDGE-R1",
    )
    assert {(f.name, f.placement.device, f.placement.how) for f in view.files if f.placement} == {
        ("EDGE-R1.cfg", ids["EDGE-R1.cfg"], How.OWN),
        ("show_version.txt", ids["EDGE-R1.cfg"], How.HOSTNAME),
        ("edge-r1_show_inventory.txt", ids["EDGE-R1.cfg"], How.NAME),
        ("leaf1/running.cfg", ids["leaf1/running.cfg"], How.OWN),
        ("leaf1/show_version.txt", ids["leaf1/running.cfg"], How.NAME),
    }
    assert [(d.name, d.hostname, len(d.companions)) for d in view.devices] == [
        ("EDGE-R1.cfg", "EDGE-R1", 2),
        ("leaf1/running.cfg", "LEAF-1", 1),
    ]

    edge, leaf = store.start(uid)
    with store.engine.connect() as conn:
        payload = json.loads(conn.execute(select(jobs.c.payload).where(jobs.c.id == edge)).one()[0])
    assert payload["file"] == ids["EDGE-R1.cfg"]
    assert payload["companions"] == [
        {"id": ids["edge-r1_show_inventory.txt"], "name": "edge-r1_show_inventory.txt"},
        {"id": ids["show_version.txt"], "name": "show_version.txt"},
    ]
    jobs_by_file = {f.name: f.job_id for f in _view(store, uid).files}
    assert jobs_by_file["show_version.txt"] == edge, "an output waits under its device's audit"
    assert jobs_by_file["leaf1/show_version.txt"] == leaf
    assert store.housekeep() == 0, "every file is still needed"


def test_pairing_by_hand(store: UploadStore) -> None:
    uid = _open(store)
    running = _staged(store, uid, _sample("cisco_ios_xe", "hardened.cfg"), "running.cfg")
    startup = _staged(store, uid, _sample("cisco_ios_xe", "weak.cfg"), "startup.cfg")  # EDGE-R1 too
    fortigate = _staged(store, uid, _sample("fortinet_fortios", "hardened.conf"), "fw.conf")
    version = _staged(store, uid, _sample("cisco_ios_xe", "show_version.txt"), "version.txt")
    store.add(uid, [running, startup, fortigate, version])
    with pytest.raises(UploadStateError, match="still being recognised"):
        store.pair(uid, version.id, running.id)
    _recognise(store)

    def placement(file_id: str) -> tuple[str | None, How | None, str | None]:
        (f,) = [f for f in _view(store, uid).files if f.id == file_id]
        assert f.placement is not None
        return f.placement.device, f.placement.how, f.placement.note

    assert placement(version.id) == (
        None,
        How.HOSTNAME,
        "matches 2 configurations (running.cfg, startup.cfg): pair it by hand",
    )
    store.pair(uid, version.id, startup.id)
    assert placement(version.id) == (startup.id, How.HAND, None)
    store.pair(uid, version.id, None)
    assert placement(version.id) == (None, How.HAND, "left out by hand: used in no audit")
    store.unpair(uid, version.id)
    assert placement(version.id)[:2] == (None, How.HOSTNAME)

    with pytest.raises(PairingError, match=r"running\.cfg is a configuration"):
        store.pair(uid, running.id, startup.id)
    with pytest.raises(PairingError, match=r"version\.txt is cisco_ios_xe output and fw\.conf"):
        store.pair(uid, version.id, fortigate.id)
    with pytest.raises(PairingError, match="isn't a configuration"):
        store.pair(uid, version.id, version.id)
    with pytest.raises(FileNotInUploadError):
        store.pair(uid, version.id, new_id())
    with pytest.raises(FileNotInUploadError):
        store.unpair(uid, new_id())

    store.pair(uid, version.id, running.id)
    store.remove_file(uid, running.id)
    assert placement(version.id) == (startup.id, How.HOSTNAME, None), "back to automatic"


def test_details_typed_by_hand_go_to_their_device_s_audit(
    store: UploadStore, queue: JobQueue
) -> None:
    """TODO M2.19: identity source 4, kept with the device until its audit is queued."""
    uid = _open(store)
    config = _staged(store, uid, _sample("cisco_ios_xe", "hardened.cfg"), "edge-r1.cfg")
    version = _staged(store, uid, _sample("cisco_ios_xe", "show_version.txt"), "version.txt")
    other = _staged(store, uid, _sample("arista_eos", "hardened.cfg"), "leaf.cfg")
    store.add(uid, [config, version, other])
    with pytest.raises(UploadStateError, match="still being recognised"):
        store.enter(uid, config.id, {"serial": "FTX1234"})
    _recognise(store)

    store.enter(uid, config.id, {"serial": " FTX1234 ", "model": "C8000V"})
    view = _view(store, uid)
    assert {f.name: f.entered for f in view.files} == {
        "edge-r1.cfg": {"model": "C8000V", "serial": "FTX1234"},
        "version.txt": {},
        "leaf.cfg": {},
    }
    assert [(d.name, d.entered) for d in view.devices] == [
        ("edge-r1.cfg", {"model": "C8000V", "serial": "FTX1234"}),
        ("leaf.cfg", {}),
    ]
    store.enter(uid, config.id, {"serial": "FTX9999"})
    assert _view(store, uid).devices[0].entered == {"serial": "FTX9999"}, "replaced, not merged"

    with pytest.raises(ManualEntryError, match=r"version\.txt is a command output"):
        store.enter(uid, version.id, {"serial": "FTX1234"})
    with pytest.raises(ManualEntryError, match="printable characters on one line only"):
        store.enter(uid, config.id, {"serial": "FTX1\nFTX2"})
    with pytest.raises(FileNotInUploadError):
        store.enter(uid, new_id(), {"serial": "FTX1234"})
    store.enter(uid, other.id, {"hardware": "7050X3"})
    store.enter(uid, other.id, {})
    assert _view(store, uid).devices[1].entered == {}, "{} clears"

    edge, leaf = store.start(uid)
    with store.engine.connect() as conn:
        payloads = {
            job_id: json.loads(text)
            for job_id, text in conn.execute(
                select(jobs.c.id, jobs.c.payload).where(jobs.c.id.in_([edge, leaf]))
            ).all()
        }
    assert payloads[edge]["entered"] == {"serial": "FTX9999"}
    assert payloads[leaf]["entered"] == {}
    with pytest.raises(UploadStateError, match="has started"):
        store.enter(uid, config.id, {})


def test_only_command_outputs_is_nothing_to_audit(store: UploadStore) -> None:
    uid = _open(store)
    store.add(uid, [_staged(store, uid, _sample("cisco_ios_xe", "show_version.txt"), "v.txt")])
    _recognise(store)
    with pytest.raises(UploadStateError, match="every file here is a command output"):
        store.start(uid)
    assert _view(store, uid).files[0].placement is not None
    assert _view(store, uid).state is UploadState.OPEN


def test_a_failed_sort_leaves_its_files_to_be_audited_alone(store: UploadStore) -> None:
    uid = _open(store)
    staged = _staged(store, uid, _sample("cisco_ios_xe", "hardened.cfg"), "r1.cfg")
    store.add(uid, [staged])
    sorter = JobQueue(store.engine, {SORT_KIND})
    (claim,) = sorter.claim("test", 1)
    sorter.finish("test", claim.id, JobState.FAILED, error="the job's worker process crashed")
    (f,) = _view(store, uid).files
    assert f.recognition is Recognition.FAILED
    assert f.placement is not None
    assert f.placement.how is How.ALONE
    assert len(store.start(uid)) == 1


def _recognise_but_crash_on(store: UploadStore, upload_id: str, bad: str) -> list[int]:
    """Run sort jobs in rounds, as a worker would, except that one holding ``bad`` fails as if
    its worker crashed; each round reads the upload, as a client polling it does, which splits
    what failed. How many jobs each round ran."""
    sorter = JobQueue(store.engine, {SORT_KIND})
    rounds = []
    while claims := sorter.claim("test", 100):
        rounds.append(len(claims))
        for claim in claims:
            payload = json.loads(claim.payload)
            if bad in payload["files"]:
                sorter.finish("test", claim.id, JobState.FAILED, error="the worker crashed")
            else:
                result = encode_result(sort_files(payload))
                sorter.finish("test", claim.id, JobState.SUCCEEDED, result=result)
        store.get(upload_id)
    return rounds


def test_a_failed_sort_is_split_until_the_file_that_fails_it_fails_alone(
    store: UploadStore,
) -> None:
    uid = _open(store)
    staged = [_staged(store, uid, f"hostname R{i}\n".encode(), f"r{i}.cfg") for i in range(40)]
    staged.append(_staged(store, uid, _sample("cisco_ios_xe", "show_version.txt"), "v.txt"))
    store.add(uid, staged)
    bad = staged[17].id
    # 41 files: one job; then 14 of 3 or fewer; then the 3 of the one that failed, one each.
    assert _recognise_but_crash_on(store, uid, bad) == [1, 14, 3]
    view = _view(store, uid)
    assert view.recognising == 0
    states = {f.id: f.recognition for f in view.files}
    assert states.pop(bad) is Recognition.FAILED
    assert set(states.values()) == {Recognition.DONE}, "every other file recognised"
    (version,) = [f for f in view.files if f.name == "v.txt"]
    assert version.recognised is not None
    assert version.recognised.kind is Kind.COMPANION
    assert len(store.start(uid)) == 41 - 1, "v.txt names EDGE-R1, which isn't here: left out"


def test_start_splits_a_failed_sort_itself(store: UploadStore) -> None:
    """A client that never reads the upload still gets its files recognised."""
    uid = _open(store)
    a = _staged(store, uid, b"hostname A\n", "a.cfg")
    b = _staged(store, uid, b"hostname B\n", "b.cfg")
    store.add(uid, [a, b])
    sorter = JobQueue(store.engine, {SORT_KIND})
    (claim,) = sorter.claim("test", 1)
    sorter.finish("test", claim.id, JobState.FAILED, error="the worker crashed")
    with pytest.raises(UploadStateError, match="2 files are still being recognised"):
        store.start(uid)
    assert len({_sort_job(store, a.id), _sort_job(store, b.id), claim.id}) == 3, "one job each"
    _recognise(store)
    assert len(store.start(uid)) == 2


def test_no_split_after_a_restart(store: UploadStore) -> None:
    """The staging key lives in memory only: after a restart no file of the job can be read,
    alone or not, so its files are audited alone, and those audits say so."""
    uid = _open(store)
    store.add(uid, [_staged(store, uid, b"hostname A\n", "a.cfg")])
    store.add(uid, [_staged(store, uid, b"hostname B\n", "b.cfg")])
    sorter = JobQueue(store.engine, {SORT_KIND})
    (claim,) = sorter.claim("test", 1)
    sorter.finish("test", claim.id, JobState.FAILED, error="the server restarted")
    payload = {**json.loads(claim.payload), "staging_key": "an earlier key"}
    with store.engine.begin() as conn:
        conn.execute(update(jobs).where(jobs.c.id == claim.id).values(payload=json.dumps(payload)))
    view = _view(store, uid)
    assert [f.recognition for f in view.files] == [Recognition.FAILED] * 2
    assert sorter.pending() == 0, "nothing queued again"
    assert len(store.start(uid)) == 2


def test_a_sort_result_is_checked_like_input(store: UploadStore) -> None:
    """A worker that a hostile file took over could send back anything: entries for files it
    wasn't given, kinds that don't exist, a hostname built to break a screen."""
    uid = _open(store)
    config = _staged(store, uid, b"hostname R1\n", "r1.cfg")
    other = _staged(store, uid, b"hostname R2\n", "r2.cfg")
    store.add(uid, [config])
    store.add(uid, [other])  # joins the same job, so the forged entry below must name neither
    sorter = JobQueue(store.engine, {SORT_KIND})
    (claim,) = sorter.claim("test", 1)
    forged = {
        "files": [
            {
                "id": config.id,
                "kind": "config",
                "vendor": "x" * 65,
                "hostname": "\u202eR1\x00" + "h" * 300,
            },
            {"id": other.id, "kind": "firmware"},
            {"id": new_id(), "kind": "config", "hostname": "INJECTED"},
            "not an object",
        ]
    }
    sorter.finish("test", claim.id, JobState.SUCCEEDED, result=encode_result(forged))
    files = {f.id: f for f in _view(store, uid).files}
    first = files[config.id].recognised
    assert first is not None
    assert (first.kind, first.vendor) == (Kind.CONFIG, None)
    assert first.hostname is not None
    assert first.hostname.startswith("R1h")
    assert len(first.hostname) == HOSTNAME_LIMIT
    second = files[other.id].recognised
    assert second is not None
    assert second.kind is Kind.UNKNOWN
    assert all(d.hostname != "INJECTED" for d in _view(store, uid).devices)


def test_uploads_and_audits_are_listed_for_the_web_ui(store: UploadStore, queue: JobQueue) -> None:
    """`recent` and `audit_jobs` (M2.76, M2.78): newest first, a device's outputs counted under
    its one audit, discarded uploads left out, and one upload's audits by name."""
    first = _open(store)
    files = {
        "b/EDGE-R1.cfg": _sample("cisco_ios_xe", "hardened.cfg"),
        "b/show_version.txt": _sample("cisco_ios_xe", "show_version.txt"),  # names EDGE-R1
        "a/leaf1.cfg": _sample("arista_eos", "hardened.cfg"),
    }
    store.add(first, [_staged(store, first, data, name) for name, data in files.items()])
    store.add(first, [Received(new_id(), "notes.docx", 10, None, "not a text file")])
    _recognise(store)
    store.start(first)
    later = utcnow() + dt.timedelta(seconds=5)
    second = store.create(label="later", frameworks=["nist_800_53r5"], vendor=None, now=later)
    dropped = _open(store)
    store.discard(dropped)

    listed = store.recent()
    assert [u.id for u in listed] == [second, first]
    brief = listed[1]
    assert (brief.state, brief.accepted, brief.refused) == (UploadState.STARTED, 3, 1)
    assert brief.audits == {"queued": 2}, "the command output shares its device's audit"
    assert listed[0].audits == {}
    assert store.recent(limit=1)[0].id == second

    audits = store.audit_jobs(upload_id=first)
    assert [(a.name, a.label, a.state) for a in audits] == [
        ("a/leaf1.cfg", "t", JobState.QUEUED),
        ("b/EDGE-R1.cfg", "t", JobState.QUEUED),
    ]
    assert store.audit_jobs(upload_id=second) == []
    assert [a.job_id for a in store.audit_jobs()] == [a.job_id for a in audits]
    assert len(store.audit_jobs(limit=1)) == 1
