"""The sort job's handler (TODO M2.06), run in this process for speed; the API and bulk tests
run it in real worker processes."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from kasauti.ingest import sort
from kasauti.ingest.devices import Kind
from kasauti.ingest.sealed import new_key
from kasauti.ingest.sort import recognise, sort_files
from kasauti.ingest.staging import STAGING_KEY_NAME, Staging
from kasauti.ingest.upload import new_id
from kasauti.jobs import JobError
from kasauti.jobs.child import set_worker_secrets
from kasauti.packs.loader import load_vendor_packs

REPO = Path(__file__).resolve().parents[3]
PACKS = REPO / "packs"
AUTHORED = REPO / "datasets" / "authored"
KEY = new_key()


@pytest.fixture(autouse=True)
def _worker_secrets() -> Iterator[None]:
    set_worker_secrets({STAGING_KEY_NAME: KEY})
    yield
    set_worker_secrets({})


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("cisco_ios_xe/hardened.cfg", ("config", "cisco_ios_xe", None, "EDGE-R1")),
        ("arista_eos/weak.cfg", ("config", "arista_eos", None, "LEAF-2")),
        ("juniper_junos/hardened.conf", ("config", "juniper_junos", None, "BR-SRX1")),
        ("fortinet_fortios/weak.conf", ("config", "fortinet_fortios", None, "FGT-BRANCH")),
        ("paloalto_panos/hardened.xml", ("config", "paloalto_panos", None, "PA-EDGE")),
        (
            "cisco_ios_xe/companions/show_version.txt",
            ("companion", "cisco_ios_xe", "show_version", "EDGE-R1"),
        ),
        (
            "cisco_ios_xe/companions/show_inventory.txt",
            ("companion", "cisco_ios_xe", "show_inventory", None),
        ),
        (
            "juniper_junos/companions/show_chassis_hardware.txt",
            ("companion", "juniper_junos", "show_chassis_hardware", None),
        ),
        (
            "fortinet_fortios/companions/get_system_status.txt",
            ("companion", "fortinet_fortios", "get_system_status", "FGT-EDGE"),
        ),
        (
            "paloalto_panos/companions/show_system_info.txt",
            ("companion", "paloalto_panos", "show_system_info", "PA-EDGE"),
        ),
    ],
)
def test_each_sample_is_recognised_as_the_audit_would_read_it(
    path: str, expected: tuple[str, str, str | None, str | None]
) -> None:
    found = recognise((AUTHORED / path).read_bytes(), load_vendor_packs(PACKS), None)
    assert (found["kind"], found["vendor"], found.get("command"), found["hostname"]) == expected


def test_a_vendor_chosen_for_the_upload_is_the_only_one_tried() -> None:
    packs = load_vendor_packs(PACKS)
    junos = (AUTHORED / "juniper_junos" / "hardened.conf").read_bytes()
    assert recognise(junos, packs, "cisco_ios_xe")["kind"] is Kind.CONFIG  # as the audit will
    version = (AUTHORED / "cisco_ios_xe" / "companions" / "show_version.txt").read_bytes()
    assert recognise(version, packs, "cisco_ios_xe")["kind"] is Kind.COMPANION
    assert recognise(version, packs, "no_such_pack") == {"kind": Kind.UNKNOWN}


@pytest.mark.parametrize("data", [b"\x00\x01" * 100, b"just some words\n", b"   \n"])
def test_what_nothing_recognises_is_unknown(data: bytes) -> None:
    assert recognise(data, load_vendor_packs(PACKS), None) == {"kind": Kind.UNKNOWN}


def _job(tmp_path: Path, files: dict[str, bytes]) -> tuple[dict[str, Any], dict[str, str]]:
    staging = Staging(tmp_path / "staging", KEY)
    upload_id = new_id()
    ids = {}
    for name, data in files.items():
        file_id = ids[name] = new_id()
        with staging.create(upload_id, file_id) as sink:
            sink.write(data)
        staging.commit(upload_id, file_id)
    payload = {
        "upload": upload_id,
        "files": list(ids.values()),
        "vendor": None,
        "staging": str(staging.root),
        "staging_key": staging.key_id,
        "packs": str(PACKS),
    }
    return payload, ids


def test_files_are_left_in_place_for_their_audit(tmp_path: Path) -> None:
    payload, ids = _job(tmp_path, {"r1.cfg": (AUTHORED / "cisco_ios_xe" / "weak.cfg").read_bytes()})
    staged = Path(payload["staging"]) / payload["upload"] / ids["r1.cfg"]
    before = staged.read_bytes()
    assert sort_files(payload) == {
        "files": [
            {"id": ids["r1.cfg"], "kind": "config", "vendor": "cisco_ios_xe", "hostname": "EDGE-R1"}
        ]
    }
    assert staged.read_bytes() == before, "still there, still sealed"


def test_a_file_just_committed_is_read_under_its_part_name(tmp_path: Path) -> None:
    payload, ids = _job(tmp_path, {"a.cfg": b"hostname A\n"})
    folder = Path(payload["staging"]) / payload["upload"]
    (folder / ids["a.cfg"]).rename(folder / f"{ids['a.cfg']}.part")  # not yet renamed
    ((found,),) = sort_files(payload).values()
    assert found == {"id": ids["a.cfg"], "kind": "unknown"}, "read, not skipped"


def test_a_removed_file_is_skipped_and_a_tampered_one_is_unknown(tmp_path: Path) -> None:
    config = (AUTHORED / "cisco_ios_xe" / "weak.cfg").read_bytes()
    payload, ids = _job(tmp_path, {"gone.cfg": b"hostname G\n", "bent.cfg": config})
    folder = Path(payload["staging"]) / payload["upload"]
    (folder / ids["gone.cfg"]).unlink()
    bent = folder / ids["bent.cfg"]
    data = bytearray(bent.read_bytes())
    data[100] ^= 0x01
    bent.write_bytes(bytes(data))
    assert sort_files(payload) == {"files": [{"id": ids["bent.cfg"], "kind": "unknown"}]}


def test_an_error_on_one_file_makes_it_unknown_not_the_job_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = (AUTHORED / "cisco_ios_xe" / "weak.cfg").read_bytes()
    payload, ids = _job(tmp_path, {"deep.cfg": b"hostname DEEP\n", "r1.cfg": config})
    real = sort.recognise

    def fragile(data: bytes, packs: Any, vendor: str | None) -> dict[str, Any]:
        if b"DEEP" in data:
            raise RecursionError("maximum recursion depth exceeded")
        return real(data, packs, vendor)

    monkeypatch.setattr(sort, "recognise", fragile)
    deep, r1 = sort_files(payload)["files"]
    assert deep == {"id": ids["deep.cfg"], "kind": "unknown"}
    assert (r1["id"], r1["kind"], r1["hostname"]) == (ids["r1.cfg"], "config", "EDGE-R1")


def test_after_a_restart_the_job_says_so(tmp_path: Path) -> None:
    payload, _ = _job(tmp_path, {"a.cfg": b"hostname A\n"})
    set_worker_secrets({STAGING_KEY_NAME: new_key()})
    with pytest.raises(JobError, match="the server restarted since they were uploaded"):
        sort_files(payload)


def test_the_payload_must_name_uploaded_files(tmp_path: Path) -> None:
    payload, _ = _job(tmp_path, {"a.cfg": b"hostname A\n"})
    with pytest.raises(JobError, match="doesn't name uploaded files"):
        sort_files({**payload, "files": ["../../etc/passwd"]})
