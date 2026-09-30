"""Signed reports (kasauti/report/sign.py; PLAN §15.3, TODO M5.12): a key made once and kept,
PAdES over the whole file, and every kind of change after signing caught offline."""

import os
import sys
from io import BytesIO
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

from kasauti.audit import audit, load_kb
from kasauti.ingest.read import read_file
from kasauti.report import sign
from kasauti.report.pdf import _cover, _Styles, render_pdf
from kasauti.report.sign import SigningError, load_or_create, sign_pdf, verify_pdf

REPO = Path(__file__).resolve().parents[3]
WEAK = REPO / "datasets" / "authored" / "cisco_ios_xe" / "weak.cfg"


@pytest.fixture(scope="module")
def report() -> bytes:
    kb = load_kb(REPO / "packs")
    result = audit(read_file(WEAK), kb)
    rules = {r.id: r for r in kb.ruleset.rules}
    return render_pdf(result, rules, generated="2026-09-30")


def test_a_signed_report_verifies_against_its_certificate(tmp_path: Path, report: bytes) -> None:
    key = load_or_create(tmp_path / "signing", host="lab")
    signed = sign_pdf(report, key)
    v = verify_pdf(signed, [key.certificate])
    assert v.ok
    assert v.signer == "Kasauti report signing (lab)"
    assert v.fingerprint == key.by.fingerprint
    assert key.by.source == "made on this server"


def test_the_key_is_made_once_and_kept(tmp_path: Path) -> None:
    first = load_or_create(tmp_path / "signing", host="lab")
    again = load_or_create(tmp_path / "signing", host="other")
    assert first.by.fingerprint == again.by.fingerprint
    if sys.platform != "win32":
        assert (tmp_path / "signing" / "key.pem").stat().st_mode & 0o777 == 0o600
        assert (tmp_path / "signing").stat().st_mode & 0o777 == 0o700


def test_half_a_key_is_refused_not_replaced(tmp_path: Path) -> None:
    load_or_create(tmp_path / "signing", host="lab")
    (tmp_path / "signing" / "cert.pem").unlink()
    with pytest.raises(SigningError, match="only one of"):
        load_or_create(tmp_path / "signing")


def test_a_changed_byte_is_caught(tmp_path: Path, report: bytes) -> None:
    key = load_or_create(tmp_path / "signing", host="lab")
    changed = bytearray(sign_pdf(report, key))
    changed[len(changed) // 3] ^= 1
    v = verify_pdf(bytes(changed), [key.certificate])
    assert not v.ok
    assert not (v.intact and v.valid)


def test_anything_added_after_signing_is_caught(tmp_path: Path, report: bytes) -> None:
    key = load_or_create(tmp_path / "signing", host="lab")
    signed = sign_pdf(report, key)
    v = verify_pdf(signed + b"\n% appended\n", [key.certificate])
    assert (v.intact, v.whole_file, v.ok) == (True, False, False)
    # A proper PDF incremental update, as an editor would save it.
    writer = IncrementalPdfFileWriter(BytesIO(signed))
    writer.root["/Lang"] = generic.pdf_string("en")
    writer.update_root()
    out = BytesIO()
    writer.write(out)
    v = verify_pdf(out.getvalue(), [key.certificate])
    assert (v.intact, v.whole_file, v.ok) == (True, False, False)


def test_a_signer_not_trusted_is_said_so(tmp_path: Path, report: bytes) -> None:
    ours = load_or_create(tmp_path / "ours", host="lab")
    other = load_or_create(tmp_path / "other", host="elsewhere")
    v = verify_pdf(sign_pdf(report, other), [ours.certificate])
    assert (v.intact, v.trusted, v.ok) == (True, False, False)


def test_an_unsigned_or_unreadable_file_is_not_signed(report: bytes) -> None:
    assert not verify_pdf(report, []).signed
    v = verify_pdf(b"%PDF-1.4 not really a pdf", [])
    assert not v.signed
    assert v.problem.startswith("not a readable PDF")


def test_an_organisation_certificate_replaces_the_servers_key(
    tmp_path: Path, report: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    made = load_or_create(tmp_path / "org-ca", host="Example Org")
    key_pem = (tmp_path / "org-ca" / "key.pem").read_bytes()
    from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
        BestAvailableEncryption,
        load_pem_private_key,
    )

    p12 = tmp_path / "org.p12"
    p12.write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"org",
            load_pem_private_key(key_pem, None),  # type: ignore[arg-type]
            made.certificate,
            None,
            BestAvailableEncryption(b"secret phrase"),
        )
    )
    monkeypatch.setenv(sign.P12_ENV, str(p12))
    monkeypatch.setenv(sign.P12_PASSWORD_ENV, "secret phrase")
    key = load_or_create(tmp_path / "unused")
    assert key.by.source == "organisation certificate"
    assert not (tmp_path / "unused").exists()
    cert = x509.load_pem_x509_certificate(key.certificate_pem)
    assert verify_pdf(sign_pdf(report, key), [cert]).ok


def test_signing_does_not_change_what_was_rendered(tmp_path: Path, report: bytes) -> None:
    """The signature is an incremental update: the rendered bytes come first, untouched."""
    key = load_or_create(tmp_path / "signing", host="lab")
    assert sign_pdf(report, key).startswith(report)
    assert os.environ.get(sign.P12_ENV) is None


def test_the_cover_says_whether_the_report_is_signed(tmp_path: Path) -> None:
    kb = load_kb(REPO / "packs")
    result = audit(read_file(WEAK), kb)
    key = load_or_create(tmp_path / "signing", host="lab")

    def signature(flowables: list[object]) -> str:
        rows = next(f for f in flowables if hasattr(f, "_cellvalues") and len(f._cellvalues) > 8)
        return next(r[1].text for r in rows._cellvalues if r[0].text == "Signature")

    assert signature(_cover(result, _Styles(), "", key.by)).startswith("PAdES, by Kasauti report")
    assert signature(_cover(result, _Styles(), "")) == "none: this report is not digitally signed"
