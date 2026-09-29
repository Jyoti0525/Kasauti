"""Kasauti generates, verifies and shows fixes; people apply them (PLAN §14.5, TODO M4.13).

No module may bring in a way to reach a device: no SSH, Telnet, NETCONF or device-API client.
"""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[2] / "kasauti"
DEVICE_CLIENTS = frozenset(
    {
        "paramiko",
        "netmiko",
        "napalm",
        "scrapli",
        "asyncssh",
        "telnetlib",
        "ncclient",
        "pexpect",
        "pan",
        "pandevice",
        "panos",
        "fortiosapi",
        "jnpr",
        "boto3",
        "botocore",
    }
)


def test_no_module_can_push_a_change_to_a_device() -> None:
    found = []
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            found += [
                f"{path.relative_to(PACKAGE)}: {n}"
                for n in names
                if n.split(".")[0] in DEVICE_CLIENTS
            ]
    assert found == []
