"""Start Kasauti as a public demonstration link, then fill it with the demonstration fleet.

The container's command (deploy/Dockerfile). The host's HTTPS front end publishes the server at a
public address; ``kasauti serve --public`` answers to that name only (backend/kasauti/api/app.py).
Everything lives on the container's own disk, so every restart brings back a fresh demonstration:
the two demo accounts and the three sample audits of tools/demo_seed.py.

    KASAUTI_PUBLIC_URL   the public https:// address; on Render, RENDER_EXTERNAL_URL is used
    PORT                 the port the front end forwards to (Render sets it; default 8000)
    KASAUTI_WORKERS      audit worker processes (default 1: small hosts have one slow CPU)
"""

from __future__ import annotations

import os
import signal
import subprocess  # nosec B404 - runs Kasauti's own commands, fixed argv, no shell
import sys
import time
import urllib.request
from pathlib import Path

APP = Path(__file__).resolve().parents[1]
DATA = Path(os.environ.get("KASAUTI_DATA_DIR", Path.home() / "data"))


def main() -> int:
    public = os.environ.get("KASAUTI_PUBLIC_URL") or os.environ.get("RENDER_EXTERNAL_URL")
    if not public:
        print("start: set KASAUTI_PUBLIC_URL to the public https:// address", file=sys.stderr)
        return 2
    port = os.environ.get("PORT", "8000")
    kasauti = Path(sys.executable).with_name("kasauti")
    server = subprocess.Popen(  # noqa: S603  # nosec B603 - fixed argv, no shell
        [
            str(kasauti if kasauti.exists() else kasauti.with_suffix(".exe")),
            "serve",
            "--data-dir",
            str(DATA),
            "--port",
            port,
            "--public",
            public,
            "--demo-accounts",
            "--workers",
            os.environ.get("KASAUTI_WORKERS", "1"),
            "--packs",
            str(APP / "packs"),
            "--web",
            str(APP / "frontend" / "dist"),
        ],
        cwd=APP,
    )
    signal.signal(signal.SIGTERM, lambda *_: server.terminate())
    local = f"http://127.0.0.1:{port}"
    if _up(f"{local}/api/health", server):
        seeded = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell
            [sys.executable, str(APP / "tools" / "demo_seed.py"), "--url", local],
            cwd=APP,
            check=False,
        )
        print("demo fleet ready" if seeded.returncode == 0 else "demo fleet not seeded", flush=True)
    return server.wait()


def _up(url: str, server: subprocess.Popen[bytes], timeout_s: float = 300) -> bool:
    """Whether the server answers ``url`` before it exits or the time runs out."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and server.poll() is None:
        try:
            with urllib.request.urlopen(url, timeout=5):  # noqa: S310  # nosec B310 - loopback
                return True
        except OSError:
            time.sleep(1)
    return False


if __name__ == "__main__":
    sys.exit(main())
