"""Audit lists, reports and the knowledge base for the web UI (TODO M2.76–M2.78, M2.82, M2.83),
end to end with real worker processes."""

from __future__ import annotations

import io
import json
import re
import zipfile
from pathlib import Path
from typing import Any

from cryptography import x509
from fastapi.testclient import TestClient

from kasauti.api.audits import summarise
from kasauti.audit import KnowledgeBase, audit
from kasauti.ingest.read import decode
from kasauti.jobs import WorkerPool
from kasauti.jobs.kinds import HANDLERS
from kasauti.report.sign import verify_pdf

REPO = Path(__file__).resolve().parents[3]
AUTHORED = REPO / "datasets" / "authored"
WEAK = AUTHORED / "cisco_ios_xe" / "weak.cfg"
HARDENED = WEAK.with_name("hardened.cfg")
AWS = AUTHORED / "aws_vpc" / "weak.json"
GUARD = {"X-Kasauti-Request": "1"}
SECRETS = re.compile(rb"PLACEHOLDER|\bpublic\b|\bprivate\b")


def _run_jobs(client: TestClient) -> None:
    state = client.app.state  # type: ignore[attr-defined]
    WorkerPool(state.jobs, HANDLERS, workers=2, secrets=state.worker_secrets).run_until_idle(
        timeout_s=120
    )


def _audited(client: TestClient, label: str, *files: Path) -> str:
    """An upload of ``files``, recognised, started and audited; its id. Each is named by its
    vendor folder and file name (``aws_vpc/weak.json``)."""
    upload_id: str = client.post("/api/uploads", json={"label": label}, headers=GUARD).json()["id"]
    for path in files:
        client.post(
            f"/api/uploads/{upload_id}/files",
            content=path.read_bytes(),
            headers={
                **GUARD,
                "Content-Type": "application/octet-stream",
                "X-File-Name": f"{path.parent.name}/{path.name}",
            },
        )
    _run_jobs(client)
    assert client.post(f"/api/uploads/{upload_id}/start", headers=GUARD).status_code == 202
    _run_jobs(client)
    return upload_id


def test_uploads_and_audits_are_listed_newest_first_with_summaries(client: TestClient) -> None:
    first = _audited(client, "core", WEAK, AWS)
    second = _audited(client, "edge", HARDENED)
    dropped = client.post("/api/uploads", json={}, headers=GUARD).json()["id"]
    assert client.delete(f"/api/uploads/{dropped}", headers=GUARD).status_code == 204

    listed = client.get("/api/uploads").json()
    assert [u["id"] for u in listed] == [second, first], "discarded ones are left out"
    assert listed[1] | {"created_at": None, "started_at": None} == {
        "id": first,
        "label": "core",
        "state": "started",
        "frameworks": ["nist_800_53r5"],
        "vendor": None,
        "created_at": None,
        "started_at": None,
        "accepted": 2,
        "refused": 0,
        "audits": {"succeeded": 2},
    }

    audits = client.get("/api/audits").json()
    assert [(a["label"], a["name"], a["state"]) for a in audits] == [
        ("edge", "cisco_ios_xe/hardened.cfg", "succeeded"),
        ("core", "aws_vpc/weak.json", "succeeded"),
        ("core", "cisco_ios_xe/weak.cfg", "succeeded"),
    ]
    mine = client.get("/api/audits", params={"upload": first}).json()
    assert [a["name"] for a in mine] == ["aws_vpc/weak.json", "cisco_ios_xe/weak.cfg"]
    weak = mine[1]["summary"]
    assert (weak["hostname"], weak["vendor"], weak["pack"]) == ("EDGE-R1", "Cisco", "cisco_ios_xe")
    assert weak["statuses"] == {"FAIL": 21, "N/A": 2}
    # Exposure raises the weak router's failures above their base (four to critical), as its
    # findings say.
    assert weak["failed_by_severity"] == {"critical": 4, "high": 5, "medium": 9, "low": 3}
    http = next(r for r in weak["rules"] if r["rule_id"] == "MGMT-HTTP-01")
    assert http["severity"] == "critical"
    assert (weak["identity_found"], weak["identity_total"]) == (3, 6)
    assert weak["scores"][0]["compliance_pct"] == 0.0
    aws = mine[0]["summary"]
    assert (aws["pack"], aws["statuses"]["FAIL"]) == ("aws_vpc", 2)

    # The summary is the result's, worked out once and kept.
    cache = client.app.state.summaries  # type: ignore[attr-defined]
    assert cache.get(mine[1]["job_id"]) is not None
    assert client.get("/api/audits", params={"upload": first}).json() == mine


def test_a_summary_is_the_results_own_counts(kb: KnowledgeBase) -> None:
    result = json.loads(audit(decode(HARDENED.read_bytes(), "hardened.cfg"), kb).canonical_json())
    summary = summarise(result)
    assert sum(summary.statuses.values()) == len(result["rules"])
    assert summary.statuses.get("FAIL", 0) == result["scores"][0]["failed"]
    assert summary.understood_pct == result["assurance"]["understood_pct"]


def test_a_failing_rule_counts_at_its_worst_findings_severity(kb: KnowledgeBase) -> None:
    result = json.loads(audit(decode(WEAK.read_bytes(), "weak.cfg"), kb).canonical_json())
    summary = summarise(result)
    for brief in summary.rules:
        fails = [f for f in result["findings"] if f["rule_id"] == brief.rule_id]
        fails = [f for f in fails if f["status"] == "FAIL"]
        if fails:
            order = ["critical", "high", "medium", "low"]
            assert brief.severity == min((f["severity"] for f in fails), key=order.index)
    assert sum(summary.failed_by_severity.values()) == summary.statuses["FAIL"]


def test_a_report_is_a_pdf_of_the_stored_result_with_no_secret(client: TestClient) -> None:
    upload_id = _audited(client, "core", WEAK, AWS)
    audits = client.get("/api/audits", params={"upload": upload_id}).json()
    by_name = {a["name"]: a["job_id"] for a in audits}
    response = client.get(f"/api/jobs/{by_name['cisco_ios_xe/weak.cfg']}/report.pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["content-disposition"] == 'attachment; filename="EDGE-R1.kasauti.pdf"'
    assert response.content.startswith(b"%PDF-")
    assert not SECRETS.search(response.content)

    bundle = client.get(f"/api/uploads/{upload_id}/reports.zip")
    assert bundle.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(bundle.content)) as zf:
        names = sorted(zf.namelist())
        assert names == ["EDGE-R1.kasauti.pdf", "vpc-0f1e2d3c4b5a69788.kasauti.pdf"]
        for name in names:
            assert zf.read(name).startswith(b"%PDF-")
            assert not SECRETS.search(zf.read(name))


def test_reports_of_what_isnt_an_audit_are_refused(client: TestClient) -> None:
    upload_id = client.post("/api/uploads", json={}, headers=GUARD).json()["id"]
    missing = "00000000-0000-4000-8000-000000000000"
    assert client.get(f"/api/jobs/{missing}/report.pdf").status_code == 404
    assert client.get(f"/api/uploads/{upload_id}/reports.zip").status_code == 404
    # A recognising job is a job, but not an audit.
    client.post(
        f"/api/uploads/{upload_id}/files",
        content=WEAK.read_bytes(),
        headers={**GUARD, "Content-Type": "application/octet-stream", "X-File-Name": "w.cfg"},
    )
    queue = client.app.state.jobs  # type: ignore[attr-defined]
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with engine.connect() as conn:
        sort_job = conn.exec_driver_sql("SELECT sort_job_id FROM upload_files").scalar_one()
    assert queue.get(sort_job).kind == "sort_files"
    assert client.get(f"/api/jobs/{sort_job}/report.pdf").status_code == 404


def test_an_audit_still_queued_has_no_report(client: TestClient) -> None:
    upload_id = client.post("/api/uploads", json={}, headers=GUARD).json()["id"]
    client.post(
        f"/api/uploads/{upload_id}/files",
        content=WEAK.read_bytes(),
        headers={**GUARD, "Content-Type": "application/octet-stream", "X-File-Name": "w.cfg"},
    )
    _run_jobs(client)
    client.post(f"/api/uploads/{upload_id}/start", headers=GUARD)
    (queued,) = client.get("/api/audits").json()
    assert (queued["state"], queued["summary"]) == ("queued", None)
    response = client.get(f"/api/jobs/{queued['job_id']}/report.pdf")
    assert (response.status_code, response.json()["detail"]) == (
        409,
        "the audit has no result; it is queued",
    )
    assert client.get(f"/api/uploads/{upload_id}/reports.zip").status_code == 409


def test_the_knowledge_base_is_described_from_the_installed_packs(
    client: TestClient, kb: KnowledgeBase
) -> None:
    body: dict[str, Any] = client.get("/api/kb").json()
    assert body["kb_version"] == kb.version
    assert [v["id"] for v in body["vendors"]] == sorted(kb.vendor_packs)
    for vendor in body["vendors"]:
        pack = kb.vendor_packs[vendor["id"]]
        assert vendor["mappings"] == len(pack.mappings)
        assert vendor["approved"] <= vendor["mappings"]
        # A pack still being taught may start with none; every seed pack has approved ones.
        assert vendor["learning"] or vendor["approved"] > 0
    frameworks = {f["id"]: f for f in body["frameworks"]}
    assert set(frameworks) == {"disa_stig", "iso_27001_2022", "nist_800_53r5"}
    stig = frameworks["disa_stig"]
    # One benchmark set per platform with a STIG; DISA publishes none for AWS security groups
    # or Huawei VRP.
    assert {v for b in stig["benchmarks"] for v in b["vendors"]} == set(kb.vendor_packs) - {
        "aws_vpc",
        "huawei_vrp",
    }
    assert all(len(b["source_sha256"]) == 64 for b in stig["benchmarks"])
    assert stig["bridge"]
    assert frameworks["iso_27001_2022"]["bridge"]
    assert len(body["rules"]) == len(kb.ruleset.rules)
    permit_any = next(r for r in body["rules"] if r["id"] == "FILTER-PERMIT-ANY-01")
    assert "cloud_filter" in permit_any["applies_to"]
    assert any(f.startswith("aws_vpc/") for f in permit_any["fixtures_fail"])
    for rule in body["rules"]:
        for control in rule["controls"]["nist_800_53r5"]:
            assert body["control_titles"][control]
        for by_vendor in rule["vendor_controls"].values():
            assert all(body["control_titles"][c] for ids in by_vendor.values() for c in ids)
    telnet = next(r for r in body["rules"] if r["id"] == "MGMT-TELNET-01")
    assert "CISC-ND-000470" in telnet["vendor_controls"]["disa_stig"]["cisco_ios_xe"]
    assert telnet["controls"]["iso_27001_2022"] == ["A.8.20"]

    detail = client.get("/api/kb/vendors/aws_vpc").json()
    assert detail["vendor"]["default_role"] == "cloud_filter"
    assert len(detail["mappings"]) == len(kb.vendor_packs["aws_vpc"].mappings)
    assert all(m["approved_by"] for m in detail["mappings"])
    assert {d["id"] for d in detail["defaults"]} >= {"sg-unmatched-denied"}
    assert client.get("/api/kb/vendors/nope").status_code == 404


def test_reports_are_signed_by_the_certificate_the_server_hands_out(client: TestClient) -> None:
    """PLAN §15.3, TODO M5.12: the report, and each one in the zip, verifies offline against
    ``GET /api/signing/certificate``, whose fingerprint ``GET /api/signing`` states."""
    about = client.get("/api/signing").json()
    assert about["signed"] is True
    assert about["source"] == "made on this server"
    pem = client.get("/api/signing/certificate")
    assert pem.headers["content-type"] == "application/x-pem-file"
    cert = x509.load_pem_x509_certificate(pem.content)

    upload_id = _audited(client, "core", WEAK, AWS)
    audits = client.get("/api/audits", params={"upload": upload_id}).json()
    job = next(a["job_id"] for a in audits if a["name"] == "cisco_ios_xe/weak.cfg")
    v = verify_pdf(client.get(f"/api/jobs/{job}/report.pdf").content, [cert])
    assert v.ok
    assert v.fingerprint == about["fingerprint"]
    bundle = client.get(f"/api/uploads/{upload_id}/reports.zip")
    with zipfile.ZipFile(io.BytesIO(bundle.content)) as zf:
        assert all(verify_pdf(zf.read(n), [cert]).ok for n in zf.namelist())
