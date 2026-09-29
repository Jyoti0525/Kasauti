from pathlib import Path

import check_licences as cl
import demo_seed
import export_schemas
import lint_content
from kasauti.ingest.devices import name_key

REPO = Path(__file__).resolve().parents[2]

RULE = """rules:
  - id: MGMT-TELNET-01
    title: Telnet not reachable
    intent: No clear-text credentials.
    domain: management_plane
    for_each: Device
    assert: not management.telnet_reachable
    severity: {base: high}
    refs: {nist_800_53r5: [CM-7, AC-99]}
    fixtures: {pass: [cisco/ok.cfg], fail: []}
"""


def test_licence_policy() -> None:
    assert cl.judge("x", "1", "MIT", runtime=True).ok
    assert cl.judge("x", "1", "MIT OR GPL-2.0-only", runtime=True).ok  # take the permissive side
    assert not cl.judge("x", "1", "AGPL-3.0", runtime=False).ok
    assert not cl.judge("PyMuPDF", "1", "AGPL-3.0", runtime=True).ok
    assert not cl.judge("redis", "8", "MIT", runtime=False).ok  # rejected by name
    assert cl.judge("chardet", "5", "LGPL-2.1", runtime=False).ok  # dev-only tool
    assert not cl.judge("chardet", "5", "LGPL-2.1", runtime=True).ok  # but never shipped
    assert cl.judge("psycopg", "3", "LGPL-3.0", runtime=True).ok
    assert not cl.judge("x", "1", "", runtime=True).ok  # unknown must be verified by hand


def test_installed_environment_passes_the_licence_gate() -> None:
    bad = [v for v in cl.evaluate() if not v.ok]
    assert not bad, bad


def test_rule_quality_gate(tmp_path: Path) -> None:
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "r.yaml").write_text(RULE, encoding="utf-8")
    problems = lint_content.rule_quality(tmp_path, tmp_path / "fixtures")
    text = "\n".join(problems)
    for key in ("on_absent", "on_unknown", "fix_intent"):
        assert key in text
    assert "at least one `fail` fixture" in text
    assert "cisco/ok.cfg not found" in text


def test_crosswalk_lint_needs_catalog_and_known_ids(tmp_path: Path) -> None:
    (tmp_path / "rules").mkdir()
    (tmp_path / "derivations").mkdir()
    (tmp_path / "rules" / "r.yaml").write_text(RULE, encoding="utf-8")
    (tmp_path / "derivations" / "d.yaml").write_text(
        (REPO / "packs" / "derivations" / "management.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    assert any("no nist_800_53r5 catalog" in p for p in lint_content.crosswalk_lint(tmp_path))
    fw = tmp_path / "frameworks" / "nist_800_53r5"
    fw.mkdir(parents=True)
    (fw / "catalog.json").write_text(
        '{"format_version": 1, "framework": "nist_800_53r5", "title": "NIST SP 800-53",'
        ' "version": "5.1.1", "source_url": "https://example.test", "licence": "public domain",'
        ' "retrieved": "2026-09-26", "controls": [{"id": "CM-7"}]}',
        encoding="utf-8",
    )
    problems = lint_content.crosswalk_lint(tmp_path)
    assert problems == ["MGMT-TELNET-01: AC-99 is not in the official NIST SP 800-53 r5 catalog"]


def test_repository_content_passes_gates() -> None:
    assert (
        lint_content.main(
            ["--packs", str(REPO / "packs"), "--fixtures", str(REPO / "datasets" / "authored")]
        )
        == 0
    )


def test_schemas_are_up_to_date() -> None:
    assert export_schemas.main(["--check"]) == 0


def test_demo_fleet_folder_pairs_command_outputs_by_folder(tmp_path: Path) -> None:
    written = demo_seed.export(tmp_path)
    assert len(written) == sum(len(files) for files in demo_seed.FLEET.values())
    for folder in {p.parent for p in written}:
        names = {name_key(p.relative_to(tmp_path).as_posix()) for p in folder.iterdir()}
        # A configuration and its command outputs say the same device: the folder's.
        assert len(names) == 1, names
