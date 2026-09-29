"""The embedding model: read exactly as its reference implementation reads it, pinned by
hash, refused when changed, and absent without breaking anything (kasauti/semantic/embed.py)."""

import hashlib
import io
import json
import struct
from pathlib import Path

import numpy as np
import pytest

from kasauti.semantic import embed
from kasauti.semantic.embed import Embedder, ModelError, ModelFile, ModelSpec, basic_tokens

REFERENCE = Path(__file__).with_name("potion_reference.json")


def test_vectors_match_the_reference_implementation(embedder: Embedder) -> None:
    """model2vec's own StaticModel.encode, recorded once (the fixture says which version):
    the same word pieces and the same vector, so the model means what it was trained to."""
    ref = json.loads(REFERENCE.read_text(encoding="utf-8"))
    inverse = {i: w for w, i in embedder.vocab.items()}
    for case in ref["cases"]:
        assert [inverse[i] for i in embedder.pieces(case["text"])] == case["pieces"]
        np.testing.assert_allclose(embedder.embed(case["text"]), case["vector"], atol=1e-6)


def test_basic_tokens_split_like_bert() -> None:
    assert basic_tokens("Info-Center loghost 10.1.1.1") == [
        "info", "-", "center", "loghost", "10", ".", "1", ".", "1", ".", "1"
    ]  # fmt: skip
    assert basic_tokens("café\tnaïve\x00") == ["cafe", "naive"]


# --- a tiny model of our own, to test loading without the real one ----------------------------


def _safetensors(matrix: np.ndarray) -> bytes:
    body = matrix.astype("<f4").tobytes()
    tensor = {"dtype": "F32", "shape": list(matrix.shape), "data_offsets": [0, len(body)]}
    header = json.dumps({"embeddings": tensor}).encode()
    return struct.pack("<Q", len(header)) + header + body


def _tiny(root: Path) -> ModelSpec:
    vocab = ["[PAD]", "[UNK]", "tel", "##net", "server"]
    vectors = np.eye(5, 3, dtype=np.float32) + 0.1
    files = {"model.safetensors": _safetensors(vectors), "vocab.txt": "\n".join(vocab).encode()}
    (root / "tiny").mkdir(parents=True)
    specs = []
    for name, data in files.items():
        (root / "tiny" / name).write_bytes(data)
        specs.append(ModelFile(name, hashlib.sha256(data).hexdigest(), len(data)))
    return ModelSpec("tiny", "example/tiny", "0" * 40, "MIT", tuple(specs))


def test_a_model_loads_when_every_file_matches_its_hash(tmp_path: Path) -> None:
    spec = _tiny(tmp_path)
    model = embed.load(spec, tmp_path)
    assert model.pieces("telnet server") == [2, 3, 4]
    assert model.pieces("zzz") == []  # unknown pieces are dropped
    assert float(np.linalg.norm(model.embed("telnet"))) == pytest.approx(1.0)
    assert not model.embed("zzz").any()


def test_a_changed_model_file_is_refused(tmp_path: Path) -> None:
    spec = _tiny(tmp_path)
    path = tmp_path / "tiny" / "model.safetensors"
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(bytes(data))
    with pytest.raises(ModelError, match="not the pinned"):
        embed.load(spec, tmp_path)


def test_a_missing_model_means_the_signals_abstain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KASAUTI_MODELS_DIR", str(tmp_path))
    monkeypatch.setattr(embed, "_LOADED", {})
    assert embed.shared() is None


def test_fetch_keeps_nothing_that_fails_its_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = _tiny(tmp_path / "source")
    monkeypatch.setattr(
        embed.urllib.request, "urlopen", lambda url, timeout: io.BytesIO(b"not the model")
    )
    with pytest.raises(ModelError, match="not the pinned"):
        embed.fetch(spec, tmp_path / "models")
    assert list((tmp_path / "models" / "tiny").iterdir()) == []


def test_fetch_downloads_only_over_https(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    spec = _tiny(tmp_path / "source")
    monkeypatch.setattr(ModelSpec, "url", lambda self, f: "http://example.org/" + f.name)
    with pytest.raises(ModelError, match="non-HTTPS"):
        embed.fetch(spec, tmp_path / "models")
