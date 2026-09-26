"""``kasauti db upgrade`` and ``kasauti db status`` (TODO M2.02)."""

from __future__ import annotations

from pathlib import Path

import pytest

from kasauti.cli.main import main
from kasauti.db import head_revision


def test_status_upgrade_status(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    var = tmp_path / "var"
    assert main(["db", "status", "--data-dir", str(var)]) == 1
    assert "no database yet" in capsys.readouterr().out
    assert not var.exists()  # asking doesn't create

    assert main(["db", "upgrade", "--data-dir", str(var)]) == 0
    assert f"schema {head_revision()} (empty -> {head_revision()})" in capsys.readouterr().out
    assert main(["db", "upgrade", "--data-dir", str(var)]) == 0
    assert "already current" in capsys.readouterr().out

    assert main(["db", "status", "--data-dir", str(var)]) == 0
    out = capsys.readouterr().out
    assert f"schema {head_revision()}, this version needs {head_revision()}" in out
    assert str((var / "kasauti.db").resolve()) in out


def test_the_data_directory_can_come_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KASAUTI_DATA_DIR", str(tmp_path / "elsewhere"))
    assert main(["db", "upgrade"]) == 0
    assert (tmp_path / "elsewhere" / "kasauti.db").is_file()


@pytest.mark.parametrize("command", ["status", "upgrade"])
def test_a_refused_url_is_reported_without_its_password(
    command: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("KASAUTI_DATABASE_URL", "postgresql://k:hunter2@db.example.org/k")
    assert main(["db", command]) == 1
    err = capsys.readouterr().err
    assert "sslmode=verify-full" in err
    assert "hunter2" not in err
