"""The Training Studio end to end (R-03, R-05, R-08; TODO M2.62-M2.68, M3.23, M3.24).

A Huawei VRP router, a vendor added as data only, is taught one pattern at a time: each teaching
is previewed against the files, needs a second person when it makes a check pass, and changes
the next audit with the server never restarted.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from kasauti.accounts import Role
from kasauti.audit import audit, load_kb
from kasauti.ingest.read import read_file

REPO = Path(__file__).resolve().parents[3]
HUAWEI = REPO / "datasets" / "authored" / "huawei_vrp"
GUARD = {"X-Kasauti-Request": "1"}
SignIn = Any


def _add(client: TestClient, name: str) -> dict[str, Any]:
    response = client.post(
        "/api/studio/files",
        content=(HUAWEI / name).read_bytes(),
        headers={**GUARD, "Content-Type": "application/octet-stream", "X-File-Name": name},
    )
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def _item(client: TestClient, pattern: str, block: str | None = None) -> dict[str, Any]:
    queue = client.get("/api/studio/packs/huawei_vrp/queue").json()
    return next(p for p in queue if p["pattern"] == pattern and p["block"] == block)


def _teach(
    client: TestClient, item: dict[str, Any], meaning: str, **choices: Any
) -> dict[str, Any]:
    suggested = next((s for s in item["suggestions"] if s["meaning"] == meaning), None)
    roles = {int(k): v for k, v in (suggested or {}).get("roles", {}).items()}
    body = {
        "pack": "huawei_vrp",
        "key": item["key"],
        "meaning": meaning,
        "tokens": [
            {"text": t["text"], "slot": t["slot"], "role": roles.get(i)}
            for i, t in enumerate(item["tokens"])
        ],
        "choices": choices or (suggested or {}).get("choices", {}),
    }
    response = client.post("/api/studio/proposals", json=body, headers=GUARD)
    assert response.status_code == 201, response.text
    proposal: dict[str, Any] = response.json()
    return proposal


def _approve(client: TestClient, proposal: dict[str, Any]) -> Any:
    return client.post(f"/api/studio/proposals/{proposal['id']}/approve", headers=GUARD)


def test_a_new_vendor_is_taught_without_a_restart(  # noqa: PLR0915 - one story, told in order
    client: TestClient, var: Path, sign_in: SignIn
) -> None:
    pid = os.getpid()
    weak = _add(client, "weak.cfg")
    _add(client, "hardened.cfg")
    assert weak["pack"] == "huawei_vrp"
    # Nothing is read yet, and nothing absent is taken as evidence: every check needs review.
    assert weak["tally"]["passed"] == weak["tally"]["failed"] == 0

    item = _item(client, "telnet server enable")
    assert item["suggestions"][0]["meaning"] == "service-on"
    assert item["suggestions"][0]["choices"] == {"service": "telnet"}
    proposal = _teach(client, item, "service-on")
    assert proposal["mapping_id"].startswith("huawei_vrp/studio-service-on-")
    assert "match: telnet server enable" in proposal["mapping"]
    flips = {(f["rule"], f["file"], f["before"], f["after"]) for f in proposal["impact"]["flips"]}
    assert ("MGMT-TELNET-01", "weak.cfg", "REVIEW", "FAIL") in flips
    # On the hardened router `undo telnet server enable` reads as off, but Telnet could still
    # reach the vty lines, which aren't taught yet: it stays REVIEW, never a guessed PASS.
    assert not any(f[0] == "MGMT-TELNET-01" and f[1] == "hardened.cfg" for f in flips)
    assert not proposal["needs_second"]
    before = client.get("/api/health").json()["kb_version"]
    approved = _approve(client, proposal)  # signed in as Asha, trainer
    assert approved.status_code == 200, approved.text
    assert client.get("/api/health").json()["kb_version"] != before

    # HTTP decides its rule alone: the hardened router now passes, so whoever proposed it can't
    # approve it (four-eyes).
    proposal = _teach(client, _item(client, "http server enable"), "service-on")
    flips = {(f["rule"], f["file"], f["after"]) for f in proposal["impact"]["flips"]}
    assert ("MGMT-HTTP-01", "hardened.cfg", "PASS") in flips
    assert proposal["needs_second"]
    refused = _approve(client, proposal)
    assert refused.status_code == 409
    assert "four-eyes" in refused.json()["detail"]
    # Another trainer is a second person, but not an approver.
    client.app.state.accounts.create(  # type: ignore[attr-defined]
        "meera", "Meera", "Kasauti-Second-Trainer", Role.TRAINER
    )
    assert client.post(
        "/api/auth/login",
        json={"username": "meera", "password": "Kasauti-Second-Trainer"},
        headers=GUARD,
    ).is_success
    refused = _approve(client, proposal)
    assert refused.status_code == 409
    assert "needs an approver" in refused.json()["detail"]
    # It waits for an approver, who signs in later and finds it.
    sign_in(client, "ravi")
    waiting = client.get("/api/studio/proposals").json()
    assert [(w["id"], w["proposed_by"]) for w in waiting] == [(proposal["id"], "asha")]
    approved = _approve(client, proposal)
    assert approved.status_code == 200, approved.text
    assert client.get("/api/studio/proposals").json() == []
    sign_in(client, "asha")
    after = client.get("/api/health").json()["kb_version"]
    assert os.getpid() == pid

    # The taught mapping lives in the data folder, with who proposed and who approved it, and
    # any audit that loads the packs with it reads Huawei Telnet now.
    stored = (var / "learned" / "huawei_vrp" / "studio.yaml").read_text(encoding="utf-8")
    assert "proposed_by: trainer:asha" in stored
    assert "approver:ravi" in stored
    # Each person is recorded in their own role: Asha approved Telnet as the trainer she is.
    assert "approver:asha" not in stored
    kb = load_kb(REPO / "packs", var / "learned")
    result = audit(read_file(HUAWEI / "weak.cfg"), kb, fixes=False)
    assert next(r for r in result.rules if r.rule_id == "MGMT-TELNET-01").status.value == "FAIL"
    assert result.kb.kb_version == after

    # A line inside a block needs the block first; then it takes the block's entity.
    block = _item(client, "user-interface vty <INT> <INT>")
    p = _teach(client, block, "remote-lines")
    assert _approve(client, p).status_code == 200
    timeout = _item(client, "idle-timeout <INT> <INT>", "user-interface vty <INT> <INT>")
    assert timeout["block_taught"]
    p = _teach(client, timeout, "line-idle-timeout")
    assert "user-interface vty <INT:first> <INT:last>" in p["mapping"]
    assert {(f["rule"], f["file"], f["after"]) for f in p["impact"]["flips"]} >= {
        ("MGMT-SESSION-TIMEOUT-01", "weak.cfg", "FAIL"),
        ("MGMT-SESSION-TIMEOUT-01", "hardened.cfg", "PASS"),
    }

    decisions = client.get("/api/studio/decisions").json()
    assert [d["action"] for d in decisions][:2] == ["propose", "approve"]
    assert any(d["action"] == "approve" and d["by"] == "ravi" and d["to_pass"] for d in decisions)

    taught = client.get("/api/studio/packs/huawei_vrp/taught").json()
    assert len(taught) == 3
    undo = client.delete(f"/api/studio/packs/huawei_vrp/taught/{taught[0]['id']}", headers=GUARD)
    assert undo.status_code == 204
    assert len(client.get("/api/studio/packs/huawei_vrp/taught").json()) == 2
    # The record names the line taught, not only the mapping's id, so a person can read it.
    latest = client.get("/api/studio/decisions").json()[0]
    assert (latest["action"], latest["line"]) == ("undo", taught[0]["match"])
    assert all(d.get("line") for d in decisions if d["action"] != "ignore")


def test_teaching_is_checked_before_it_is_stored(client: TestClient) -> None:
    _add(client, "weak.cfg")
    item = _item(client, "idle-timeout <INT> <INT>", "user-interface vty <INT> <INT>")
    # Its block isn't taught yet, so a line-timeout meaning has nothing to attach to.
    body = {
        "pack": "huawei_vrp",
        "key": item["key"],
        "meaning": "line-idle-timeout",
        "tokens": [
            {"text": t["text"], "slot": t["slot"], "role": role}
            for t, role in zip(item["tokens"], (None, None, None), strict=True)
        ],
        "choices": {},
    }
    refused = client.post("/api/studio/proposals", json=body, headers=GUARD)
    assert refused.status_code == 409
    assert "mark which word is: Minutes" in refused.json()["detail"]
    body["tokens"][1]["role"] = "minutes"
    body["tokens"][2]["role"] = "seconds"
    refused = client.post("/api/studio/proposals", json=body, headers=GUARD)
    assert refused.status_code == 409
    assert "teach that block's line first" in refused.json()["detail"]
    # A masked secret is never a literal word.
    community = _item(client, "snmp-agent community write cipher <STR>")
    assert "****" in [t["text"] for t in community["tokens"]]
    assert all(t["slot"] == "STR" for t in community["tokens"] if t["text"] == "****")


def test_teaching_needs_a_trainer(client: TestClient) -> None:
    _add(client, "weak.cfg")
    item = _item(client, "telnet server enable")
    # A new sign-up is an auditor: it sees the Studio but can't teach it.
    signup = {"username": "kiran", "name": "Kiran", "password": "a long enough passphrase"}
    assert client.post("/api/auth/signup", json=signup, headers=GUARD).status_code == 201
    assert client.get("/api/studio").status_code == 200
    body = {"pack": "huawei_vrp", "key": item["key"], "meaning": "service-on", "tokens": []}
    refused = client.post("/api/studio/proposals", json=body, headers=GUARD)
    assert (refused.status_code, refused.json()["detail"]) == (
        403,
        "this needs the trainer role; you are auditor",
    )


def test_ignored_patterns_leave_the_queue(client: TestClient) -> None:
    _add(client, "weak.cfg")
    item = _item(client, "return")
    response = client.post(
        "/api/studio/ignore",
        json={"pack": "huawei_vrp", "key": item["key"]},
        headers=GUARD,
    )
    assert response.status_code == 204
    queue = client.get("/api/studio/packs/huawei_vrp/queue").json()
    assert all(p["key"] != item["key"] for p in queue)


def test_files_stay_in_memory_only(client: TestClient, var: Path) -> None:
    weak = _add(client, "weak.cfg")
    assert b"BR-HW-AR1" not in b"".join(p.read_bytes() for p in var.rglob("*") if p.is_file())
    assert client.delete(f"/api/studio/files/{weak['id']}", headers=GUARD).status_code == 204
    assert client.get("/api/studio").json()["files"] == []


def test_a_suggestion_needs_a_word_naming_its_subject(client: TestClient) -> None:
    _add(client, "hardened.cfg")
    _add(client, "weak.cfg")
    # "version" is shared with SSH version 1, but nothing on the line is about SSH: suggesting
    # it would let one careless approval fail SSH on a router that runs only version 2.
    snmp = _item(client, "snmp-agent sys-info version v3")
    assert all(s["meaning"] != "ssh-v1-allowed" for s in snmp["suggestions"])
    # A word naming the subject outweighs common ones: SSH version 1 before "a service on".
    ssh = _item(client, "ssh server compatible-ssh1x enable")
    assert ssh["suggestions"][0]["meaning"] == "ssh-v1-allowed"
    stamps = _item(client, "info-center timestamp log date")
    assert [s["meaning"] for s in stamps["suggestions"]] == ["log-timestamps"]
    # The vendor's negation word turns a service off; a TACACS+ server isn't a time source.
    off = _item(client, "undo telnet server enable")
    assert off["suggestions"][0]["meaning"] == "service-off"
    assert all(s["meaning"].startswith("service-") for s in off["suggestions"])
    tacacs = _item(
        client, "hwtacacs-server authentication <IP> <INT>", "hwtacacs-server template tac1"
    )
    assert tacacs["suggestions"] == []
    ntp = _item(client, "ntp-service unicast-server <IP>")
    assert [s["meaning"] for s in ntp["suggestions"]] == ["time-server"]
    # A faint likeness is no suggestion at all.
    assert _item(client, "acl number <INT>")["suggestions"] == []
