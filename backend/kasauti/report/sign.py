"""Signed reports (PLAN §15.3; TODO M5.12).

Every PDF report carries a PAdES digital signature (pyHanko, MIT) over the whole file. Any PDF
reader shows whether the report was changed after signing, and ``kasauti verify report.pdf``
checks it offline.

**The key.** By default, one made on this server the first time it is needed: an ECDSA P-256
key and a self-signed certificate naming Kasauti and the host, in ``<data dir>/signing``, the
folder and files readable by their owner only (like an SSH host key). A PDF reader shows such a
signature as intact but its signer as unknown until the certificate is trusted; ``GET
/api/signing/certificate`` hands it out for that. An organisation's own certificate (a PKCS#12
file, ``KASAUTI_SIGNING_P12`` and ``KASAUTI_SIGNING_P12_PASSWORD``) replaces it. An officer's
Class-3 DSC on a USB token (PKCS#11) is the next step: pyHanko supports it, but it is not wired
up or tested without a token.

**Level.** PAdES baseline B-B: the signing time is the server's own clock, with no trusted
timestamp. Verification is offline: only the certificates it is given are trusted; nothing is
fetched (no system trust store, no revocation lookups).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import socket
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from kasauti.log import get_logger

log = get_logger(__name__)

P12_ENV = "KASAUTI_SIGNING_P12"
P12_PASSWORD_ENV = "KASAUTI_SIGNING_P12_PASSWORD"  # noqa: S105  # nosec B105 - a variable's name
FIELD = "KasautiReport"
REASON = "Kasauti compliance audit report"


class SigningError(RuntimeError):
    """The signing key can't be made or read. User-safe text."""


@dataclass(frozen=True, slots=True)
class SignedBy:
    """What a report says about its own signature (it is rendered before it is signed)."""

    name: str
    fingerprint: str
    """SHA-256 of the certificate (DER), hex."""
    source: str


@dataclass(frozen=True)
class SigningKey:
    signer: object
    """A ``pyhanko.sign.signers.SimpleSigner``."""
    certificate: x509.Certificate
    by: SignedBy

    @property
    def certificate_pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)


def fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _common_name(cert: x509.Certificate) -> str:
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(names[0].value) if names else cert.subject.rfc4514_string()


def _private(path: Path, data: bytes) -> None:
    """Write ``data`` readable by its owner only, created that way (never widened after)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _create(folder: Path, host: str) -> None:
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, f"Kasauti report signing ({host})"[:64]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Kasauti"),
        ]
    )
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    _private(
        folder / "key.pem",
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    (folder / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    log.info("signing_key_created", folder=str(folder), fingerprint=fingerprint(cert))


def load_or_create(folder: Path, *, host: str | None = None) -> SigningKey:
    """The signing key: an organisation's PKCS#12 certificate when ``KASAUTI_SIGNING_P12``
    names one, else the key in ``folder``, made there the first time."""
    from pyhanko.sign import signers  # noqa: PLC0415 - pyHanko only when signing

    p12 = os.environ.get(P12_ENV)
    if p12:
        password = os.environ.get(P12_PASSWORD_ENV, "").encode() or None
        signer = signers.SimpleSigner.load_pkcs12(p12, passphrase=password)  # type: ignore[no-untyped-call]
        if signer is None:
            raise SigningError(f"{P12_ENV}: can't read a key and certificate from {p12}")
        cert = x509.load_der_x509_certificate(signer.signing_cert.dump())
        return SigningKey(
            signer,
            cert,
            SignedBy(_common_name(cert), fingerprint(cert), "organisation certificate"),
        )
    key, cert_path = folder / "key.pem", folder / "cert.pem"
    if not key.exists() and not cert_path.exists():
        _create(folder, host or socket.gethostname())
    elif not (key.exists() and cert_path.exists()):
        raise SigningError(
            f"{folder} holds only one of key.pem and cert.pem; restore the other or remove both "
            "to make a new key (reports signed before can then only be checked with the old "
            "certificate)"
        )
    signer = signers.SimpleSigner.load(  # type: ignore[no-untyped-call]
        str(key), str(cert_path), key_passphrase=None
    )
    if signer is None:
        raise SigningError(f"can't read the signing key in {folder}")
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return SigningKey(
        signer, cert, SignedBy(_common_name(cert), fingerprint(cert), "made on this server")
    )


def sign_pdf(pdf: bytes, key: SigningKey) -> bytes:
    """``pdf`` with a PAdES signature over the whole file, added as an incremental update."""
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter  # noqa: PLC0415
    from pyhanko.sign import fields, signers  # noqa: PLC0415

    writer = IncrementalPdfFileWriter(BytesIO(pdf))
    meta = signers.PdfSignatureMetadata(
        field_name=FIELD,
        md_algorithm="sha256",
        subfilter=fields.SigSeedSubFilter.PADES,
        reason=REASON,
        name=key.by.name,
    )
    out = BytesIO()
    signers.sign_pdf(writer, meta, signer=key.signer, output=out)  # type: ignore[arg-type]
    return out.getvalue()


@dataclass(frozen=True, slots=True)
class Verification:
    signed: bool
    intact: bool = False
    """The signed bytes are unchanged."""
    valid: bool = False
    """The signature itself checks out against the certificate in it."""
    trusted: bool = False
    """That certificate is one of those given as trusted."""
    whole_file: bool = False
    """Nothing was added to the file after it was signed."""
    signer: str = ""
    fingerprint: str = ""
    signed_at: str = ""
    problem: str = ""

    @property
    def ok(self) -> bool:
        return self.signed and self.intact and self.valid and self.trusted and self.whole_file


def verify_pdf(pdf: bytes, trusted: list[x509.Certificate]) -> Verification:
    """Check the report's signature offline against ``trusted`` certificates only."""
    from asn1crypto import x509 as asn1_x509  # noqa: PLC0415
    from pyhanko.pdf_utils.misc import PdfReadError  # noqa: PLC0415
    from pyhanko.pdf_utils.reader import PdfFileReader  # noqa: PLC0415
    from pyhanko.sign.validation import validate_pdf_signature  # noqa: PLC0415
    from pyhanko.sign.validation.status import SignatureCoverageLevel  # noqa: PLC0415
    from pyhanko_certvalidator import ValidationContext  # noqa: PLC0415

    try:
        reader = PdfFileReader(BytesIO(pdf))
        sigs = [s for s in reader.embedded_signatures if s.field_name == FIELD]
    except (PdfReadError, ValueError, KeyError) as e:
        return Verification(False, problem=f"not a readable PDF: {e}")
    if not sigs:
        return Verification(False, problem="the file carries no Kasauti signature")
    roots = [
        asn1_x509.Certificate.load(c.public_bytes(serialization.Encoding.DER)) for c in trusted
    ]
    # Only the certificates given: no system trust store, nothing fetched.
    context = ValidationContext(trust_roots=roots, allow_fetching=False)
    sig = sigs[-1]
    try:
        status = validate_pdf_signature(sig, context)
    except Exception as e:
        return Verification(True, problem=f"the signature can't be checked: {type(e).__name__}")
    cert = x509.load_der_x509_certificate(status.signing_cert.dump())
    return Verification(
        signed=True,
        intact=bool(status.intact),
        valid=bool(status.valid),
        trusted=bool(status.trusted),
        whole_file=status.coverage is SignatureCoverageLevel.ENTIRE_FILE,
        signer=_common_name(cert),
        fingerprint=fingerprint(cert),
        signed_at=status.signer_reported_dt.isoformat() if status.signer_reported_dt else "",
    )
