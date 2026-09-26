"""Ingestion (TODO M1.01) and kind-preserving masking (M2.08, first cut)."""

import codecs
import hashlib
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from kasauti.ingest.mask import MASK, mask_secrets
from kasauti.ingest.read import MAX_BYTES, IngestError, decode, looks_binary, read_file


def test_utf8_is_decoded_and_hashed_over_the_original_bytes() -> None:
    data = b"hostname R1\n"
    art = decode(data, "r1.cfg")
    assert art.text == "hostname R1\n"
    assert art.encoding == "utf-8"
    assert art.sha256 == hashlib.sha256(data).hexdigest()


def test_bom_marked_utf16_is_text_not_binary() -> None:
    data = codecs.BOM_UTF16_LE + "hostname R1\n".encode("utf-16-le")
    art = decode(data, "r1.cfg")
    assert art.text.strip() == "hostname R1"


def test_legacy_encoding_is_detected() -> None:
    data = ("description Zürich Überlandleitung, Größe ändern\n" * 20).encode("cp1252")
    art = decode(data, "r1.cfg")
    assert "Zürich" in art.text


def test_binary_files_are_refused() -> None:
    with pytest.raises(IngestError, match="binary"):
        decode(b"\x7fELF\x02\x01\x01\x00" + bytes(range(256)) * 4, "firmware.bin")
    assert looks_binary(b"\x00abc")
    assert not looks_binary(b"interface Gi1\n shutdown\n")


def test_empty_and_oversized_inputs_are_refused(tmp_path: Path) -> None:
    with pytest.raises(IngestError, match="empty"):
        decode(b"  \n", "empty.cfg")
    with pytest.raises(IngestError, match="limit"):
        decode(b"x" * (MAX_BYTES + 1), "big.cfg")
    with pytest.raises(IngestError, match="cannot read"):
        read_file(tmp_path / "missing.cfg")


@pytest.mark.parametrize(
    ("line", "masked"),
    [
        ("enable password 0 hunter2", "enable password 0 ****"),
        ("enable secret 9 $9$abc$def", "enable secret 9 ****"),
        (
            "username a privilege 15 password 7 0822455D0A16",
            "username a privilege 15 password 7 ****",
        ),
        (" key 7 070C285F4D06", " key 7 ****"),
        ("snmp-server community public RO", "snmp-server community **** RO"),
        ("snmp-server community s3cret RW 10", "snmp-server community **** RW 10"),
        (
            "snmp-server host 10.0.0.9 version 2c s3cret",
            "snmp-server host 10.0.0.9 version 2c ****",
        ),
        (
            "snmp-server host 10.0.0.9 version 3 priv nmsuser",
            "snmp-server host 10.0.0.9 version 3 priv nmsuser",
        ),
        (
            "snmp-server user u g v3 auth sha AUTHPW priv aes 128 PRIVPW",
            "snmp-server user u g v3 auth sha **** priv aes 128 ****",
        ),
        (
            "ntp authentication-key 1 hmac-sha2-256 KEYDATA",
            "ntp authentication-key 1 hmac-sha2-256 ****",
        ),
        ('encrypted-password "$6$salt$hash"', 'encrypted-password "****"'),
        ("set password ENC SH2abcdef", "set password ENC ****"),
        ('pre-shared-key ascii-text "$9$abc"', 'pre-shared-key ascii-text "****"'),
        ("add name=admin password=Secret1", "add name=admin password=****"),
        ("crypto key generate rsa modulus 2048", "crypto key generate rsa modulus 2048"),
        ("key chain OSPF-KEYS", "key chain OSPF-KEYS"),
        ("set community 65000:100 additive", "set community 65000:100 additive"),
        ("transport input ssh", "transport input ssh"),
    ],
)
def test_masking_keeps_the_kind_and_hides_the_value(line: str, masked: str) -> None:
    assert mask_secrets(line) == masked


@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=80))
def test_masking_never_crashes_and_is_idempotent(text: str) -> None:
    once = mask_secrets(text)
    assert mask_secrets(once) == once
    assert MASK not in text or MASK in once
