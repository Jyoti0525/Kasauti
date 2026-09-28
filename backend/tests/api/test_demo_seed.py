"""``tools/demo_seed.py`` sends files only to a Kasauti on this machine."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[3] / "tools" / "demo_seed.py"
_SPEC = importlib.util.spec_from_file_location("demo_seed", _PATH)
assert _SPEC
assert _SPEC.loader
demo_seed = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(demo_seed)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8000",
        "http://127.0.0.1:8000/",
        "http://localhost:9000",
        "http://[::1]:8000",
    ],
)
def test_loopback_is_accepted(url: str) -> None:
    assert demo_seed.Api(url).base == url.rstrip("/")


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8000@evil.example",  # userinfo, the host is evil.example
        "http://127.0.0.1.evil.example:8000",
        "https://127.0.0.1:8000",
        "file:///etc/passwd",
        "http://10.0.0.5:8000",
        "http://127.0.0.1:8000/elsewhere",
        "http://user@127.0.0.1:8000",
    ],
)
def test_anything_else_is_refused(url: str) -> None:
    with pytest.raises(SystemExit, match="loopback"):
        demo_seed.Api(url)
