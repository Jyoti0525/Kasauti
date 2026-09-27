"""A bulk upload of 100 mixed files (TODO M2.09; R-04's acceptance test; PLAN §22's budget).

Generated from the authored corpus, so it holds no configuration that isn't already in the
repository: every sample is renamed per copy (duplicates are refused, rightly) and some are
grown to the sizes real devices export, with the objects each vendor has most of (interfaces,
address objects, routes, prefix lists). Mixed in: a zip with folders, and files an upload must
report rather than audit.

Each row names what should become of it: ``audited``, ``failed`` (its audit job fails with a
reason) or ``refused`` (the intake refuses it, with a reason).
"""

from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

AUTHORED = Path(__file__).resolve().parents[3] / "datasets" / "authored"

SAMPLES = {
    "cisco_ios_xe": ("cfg", "EDGE-R1", "EDGE-R1"),
    "arista_eos": ("cfg", "LEAF-1", "LEAF-2"),
    "juniper_junos": ("conf", "BR-SRX1", "BR-SRX1"),
    "fortinet_fortios": ("conf", "FGT-EDGE", "FGT-BRANCH"),
    "paloalto_panos": ("xml", "PA-EDGE", "PA-BRANCH"),
}
"""Vendor: (suffix, host name in hardened, host name in weak)."""

SMALL, MEDIUM, LARGE = 0, 1_500, 5_000
"""Lines to grow a sample by: as authored, a branch device, a large core or edge device."""


@dataclass(frozen=True)
class Row:
    name: str
    data: bytes
    outcome: str
    """``audited``, ``failed``, ``refused``, or ``left out`` (a command output with no
    configuration of its host in the upload: reported, and in no audit)."""
    vendor: str | None = None


def _grow(vendor: str, text: str, lines: int) -> str:
    """Add about ``lines`` lines of the vendor's most numerous objects, where the device puts
    them."""
    if lines == 0:
        return text
    if vendor in ("cisco_ios_xe", "arista_eos"):
        port = "GigabitEthernet1/0/" if vendor == "cisco_ios_xe" else "Ethernet"
        block = "".join(
            f"interface {port}{i}\n description access port {i}\n switchport mode access\n"
            f" switchport access vlan {100 + i % 50}\n spanning-tree portfast\n no shutdown\n!\n"
            for i in range(1, lines // 7 + 1)
        )
        head, end = text.rsplit("end\n", 1)
        return head + block + "end\n" + end
    if vendor == "juniper_junos":
        entries = "".join(
            f"        10.{i // 250}.{i % 250}.0/24;\n" for i in range(max(1, lines - 4))
        )
        return text + f"policy-options {{\n    prefix-list BULK {{\n{entries}    }}\n}}\n"
    if vendor == "fortinet_fortios":
        edits = "".join(
            f"    edit {i}\n        set dst 10.{i // 250}.{i % 250}.0 255.255.255.0\n"
            f'        set gateway 192.0.2.1\n        set device "wan1"\n    next\n'
            for i in range(1, lines // 5 + 1)
        )
        return text + f"config router static\n{edits}end\n"
    entries = "".join(
        f'      <entry name="net-{i}">\n        <ip-netmask>10.{i // 250}.{i % 250}.0/24'
        "</ip-netmask>\n      </entry>\n"
        for i in range(lines // 3)
    )
    return text.replace("  </shared>", f"    <address>\n{entries}    </address>\n  </shared>", 1)


def config(vendor: str, variant: str, number: int, lines: int = SMALL) -> Row:
    suffix, hardened, weak = SAMPLES[vendor]
    host = hardened if variant == "hardened" else weak
    text = (AUTHORED / vendor / f"{variant}.{suffix}").read_text(encoding="utf-8")
    text = _grow(vendor, text.replace(host, f"{host}-{number:03d}"), lines)
    name = f"{vendor}/{host.lower()}-{number:03d}.{suffix}"
    return Row(name, text.encode(), "audited", vendor)


def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _companion(vendor: str, name: str) -> bytes:
    return (AUTHORED / vendor / "companions" / name).read_bytes()


def corpus() -> tuple[list[Row], list[Row]]:
    """The files sent on their own, and the rows the zip (sent as ``site-b.zip``) becomes."""
    vendors = list(SAMPLES)
    sizes = [LARGE] * 6 + [MEDIUM] * 20 + [SMALL] * 51
    direct = [
        config(vendors[i % 5], ("weak", "hardened")[i // 5 % 2], i, lines)
        for i, lines in enumerate(sizes)
    ]
    first = direct[-1]
    utf16 = config("cisco_ios_xe", "weak", 900)
    direct += [
        Row(
            "windows-export.cfg",
            b"\xff\xfe" + utf16.data.decode().encode("utf-16-le"),
            "audited",
            "cisco_ios_xe",
        ),
        Row("copy-of-" + Path(first.name).name, first.data, "refused"),  # same content again
        Row("empty.txt", b"", "refused"),
        Row("diagram.cfg", b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 40, "refused"),
        Row("handover.docx", b"PK\x03\x04 not a configuration", "refused"),
        Row("notes.txt", b"Change window: Saturday 02:00.\nCall the NOC first.\n", "failed"),
        # Audited, but read line by line: every rule is left for review.
        Row("cut-off.xml", config("paloalto_panos", "weak", 901).data[:2000], "audited"),
        # The first device's `show version` (host EDGE-R1-000): audited with its configuration.
        Row(
            "show_version.txt",
            _companion("cisco_ios_xe", "show_version.txt").replace(b"EDGE-R1", b"EDGE-R1-000"),
            "audited",
        ),
    ]
    inside = [
        config(vendors[i % 5], "weak", 500 + i, MEDIUM if i < 3 else SMALL) for i in range(12)
    ]
    archive = {f"site-b/{Path(r.name).name}": r.data for r in inside}
    archive["site-b/README.md"] = b"# Site B exports\n"
    archive["site-b/older.zip"] = _zip({"old.cfg": b"hostname OLD\n"})
    archive["site-b/fw/get_system_status.txt"] = _companion(
        "fortinet_fortios", "get_system_status.txt"
    )
    zipped = [Row(f"site-b.zip/{n}", d, "audited") for n, d in archive.items()]
    zipped = [Row(r.name, r.data, _zip_outcome(r.name)) for r in zipped]
    return direct, zipped


def _zip_outcome(name: str) -> str:
    if re.search(r"\.(md|zip)$", name):
        return "refused"
    # The zip's one command output names FGT-EDGE, and no configuration here is that host.
    return "left out" if name.endswith(".txt") else "audited"


def zipped_bytes(rows: list[Row]) -> bytes:
    return _zip({r.name.removeprefix("site-b.zip/"): r.data for r in rows})
