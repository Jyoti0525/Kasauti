"""Fill a running Kasauti with a demonstration fleet, through its public API (TODO M2.76 demo).

Uploads the authored sample configurations (``datasets/authored``, all illustrative, no real
device) as three audits, the way the web UI does: one request per file, command outputs paired
with their device, then started. It uses only the standard library and talks only to the
loopback server, so it runs on an air-gapped laptop.

    uv run kasauti serve --data-dir var/demo        # a separate, empty database for the demo
    uv run python tools/demo_seed.py                # in another terminal

Then open http://127.0.0.1:8000/. Run it again for another round of the same audits: the
dashboard counts each device once, at its latest audit.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

REPO = Path(__file__).resolve().parents[1]
AUTHORED = REPO / "datasets" / "authored"
GUARD = {"X-Kasauti-Request": "1"}

FLEET: dict[str, list[str]] = {
    "Data-centre core and edge": [
        "cisco_ios_xe/weak.cfg",
        "cisco_ios_xe/companions/show_version.txt",
        "cisco_ios_xe/companions/show_inventory.txt",
        "arista_eos/hardened.cfg",
        "arista_eos/companions/show_version.txt",
        "juniper_junos/weak.conf",
        "juniper_junos/companions/show_version.txt",
        "juniper_junos/companions/show_chassis_hardware.txt",
    ],
    "Branch firewalls": [
        "paloalto_panos/weak.xml",
        "fortinet_fortios/hardened.conf",
        "fortinet_fortios/companions/get_system_status.txt",
    ],
    "AWS production VPC": ["aws_vpc/weak.json"],
}


class Api:
    def __init__(self, base: str) -> None:
        # Parsed, not prefix-matched: "http://127.0.0.1:8000@elsewhere" is a userinfo, not a host.
        url = urlsplit(base)
        if (
            url.scheme != "http"
            or url.hostname not in {"127.0.0.1", "localhost", "::1"}
            or url.username is not None
            or url.path.strip("/")
            or url.query
            or url.fragment
        ):
            raise SystemExit("demo_seed talks to a loopback Kasauti only: http://127.0.0.1:PORT")
        self.base = base.rstrip("/")

    def call(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        request = urllib.request.Request(  # noqa: S310  # nosec B310  # base is loopback http
            self.base + path,
            data=body,
            method=method,
            headers={**(GUARD if method != "GET" else {}), **(headers or {})},
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310  # nosec B310
                raw = response.read()
        except urllib.error.HTTPError as err:
            raise SystemExit(
                f"{method} {path}: {err.code} {err.read().decode(errors='replace')}"
            ) from None
        return json.loads(raw) if raw else None

    def json(self, method: str, path: str, body: object) -> Any:
        return self.call(
            method, path, json.dumps(body).encode(), {"Content-Type": "application/json"}
        )


def seed(api: Api) -> list[str]:
    started = []
    for label, files in FLEET.items():
        upload = api.json("POST", "/api/uploads", {"label": label})
        uid = upload["id"]
        for rel in files:
            path = AUTHORED / rel
            api.call(
                "POST",
                f"/api/uploads/{uid}/files",
                path.read_bytes(),
                {"Content-Type": "application/octet-stream", "X-File-Name": quote(rel)},
            )
        view = _wait(api, uid, lambda v: v["recognising"] == 0, "recognised")
        _pair_strays(api, uid, view)
        api.call("POST", f"/api/uploads/{uid}/start")
        started.append(uid)
        print(f"started  {label}: {len(view['devices'])} device(s)")
    for uid in started:
        _wait(
            api,
            uid,
            lambda v: all(
                f["job_state"] not in {"queued", "running"} for f in v["files"] if f["accepted"]
            ),
            "audited",
        )
    return started


def _pair_strays(api: Api, uid: str, view: dict[str, Any]) -> None:
    """A command output that names no host (``show inventory``) goes with the configuration from
    the same vendor folder, as a person would pair it on the New audit screen. One that names
    another host is left as Kasauti left it: it belongs to another device."""
    configs = {f["name"].split("/")[0]: f["id"] for f in view["files"] if f["kind"] == "config"}
    for f in view["files"]:
        if f["kind"] == "companion" and f["device"] is None and f["hostname"] is None:
            target = configs.get(f["name"].split("/")[0])
            if target:
                api.json("PUT", f"/api/uploads/{uid}/files/{f['id']}/pairing", {"config": target})


def _wait(api: Api, uid: str, done: Any, what: str, timeout_s: float = 300) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        view: dict[str, Any] = api.call("GET", f"/api/uploads/{uid}")
        if done(view):
            return view
        time.sleep(0.5)
    raise SystemExit(
        f"upload {uid} not {what} after {timeout_s:.0f} s: is `kasauti serve` running workers?"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="the running Kasauti")
    args = parser.parse_args(argv)
    api = Api(args.url)
    api.call("GET", "/api/health")
    seed(api)
    for audit in api.call("GET", "/api/audits?limit=50"):
        s = audit["summary"]
        if s:
            score = s["scores"][0]
            print(
                f"  {s['hostname'] or audit['name']:<24} {s['pack']:<18} "
                f"compliance {score['compliance_pct']}%  coverage {score['coverage_pct']}%"
            )
    print(f"open {args.url}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
