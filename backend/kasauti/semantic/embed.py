"""Sentence embeddings for the semantic engine (PLAN §10.2 S5; TODO M3.12, M3.13).

**The model.** ``potion-base-8M`` (Minish Lab, MIT): a *static* embedding model, distilled from
the BAAI bge-base-en-v1.5 sentence transformer into one 256-dimensional vector per word piece.
A sentence's vector is the mean of its word pieces' vectors, normalised. That makes it small
(30 MB), fast (microseconds per line on a laptop CPU, no GPU) and light enough for the 512 MB
demonstration host, which a transformer and PyTorch are not. The PLAN §10.2 shortlist of
transformer encoders stays the upgrade path, promoted only if it beats this one on the
leave-one-vendor-out evaluation (``eval/harness/lovo.py``).

**No network at run time.** The files are fetched once, at setup (``kasauti models fetch``, or
the container build), from a pinned revision; each is checked against its SHA-256 here, and
checked again every time the model is loaded, so a swapped or corrupted file is refused, never
used (PLAN §17 "Models", TODO M5.09). The model is read with numpy alone: the tokenizer (BERT
WordPiece, lower-cased) and the safetensors reader are the few lines below, so no library that
can talk to a model hub is installed. Without the model, the signals that need it abstain and
the Studio's other signals still suggest (PLAN §10.6, the degradation ladder).
"""

from __future__ import annotations

import hashlib
import json
import os
import unicodedata
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import numpy as np
import numpy.typing as npt

from kasauti.log import get_logger

log = get_logger(__name__)

Vector = npt.NDArray[np.float32]


@dataclass(frozen=True, slots=True)
class ModelFile:
    name: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class ModelSpec:
    name: str
    repo: str
    revision: str
    licence: str
    files: tuple[ModelFile, ...]

    def url(self, file: ModelFile) -> str:
        return f"https://huggingface.co/{self.repo}/resolve/{self.revision}/{file.name}"


POTION_8M: Final = ModelSpec(
    name="potion-base-8M",
    repo="minishlab/potion-base-8M",
    revision="bf8b056651a2c21b8d2565580b8569da283cab23",
    licence="MIT",
    files=(
        ModelFile(
            "model.safetensors",
            "f65d0f325faadc1e121c319e2faa41170d3fa07d8c89abd48ca5358d9a223de2",
            30236760,
        ),
        ModelFile(
            "vocab.txt",
            "1394523a67ddd404a825428018c0582a6998bcfa044ecbcbf1f4d71adb94c61c",
            219690,
        ),
    ),
)
MODEL: Final = POTION_8M


def models_dir() -> Path:
    """Where models live: ``KASAUTI_MODELS_DIR``, else ``~/.kasauti/models``."""
    env = os.environ.get("KASAUTI_MODELS_DIR")
    return Path(env) if env else Path.home() / ".kasauti" / "models"


class ModelError(RuntimeError):
    """A model file is missing, or isn't the file the manifest pins."""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(spec: ModelSpec = MODEL, root: Path | None = None) -> Path:
    """Download ``spec`` into ``root`` (setup time only), checking every file's SHA-256. A file
    already present with the right hash is kept. Returns the model's directory."""
    target = (root or models_dir()) / spec.name
    target.mkdir(parents=True, exist_ok=True)
    for file in spec.files:
        path = target / file.name
        if path.exists() and _sha256(path) == file.sha256:
            continue
        url = spec.url(file)
        if not url.startswith("https://"):  # the manifest is ours; this guards edits to it
            raise ModelError(f"refusing a non-HTTPS model URL: {url}")
        tmp = path.with_suffix(path.suffix + ".part")
        h = hashlib.sha256()
        opened = urllib.request.urlopen(url, timeout=60)  # noqa: S310  # nosec B310
        with opened as resp, tmp.open("wb") as out:
            for chunk in iter(lambda: resp.read(1 << 20), b""):
                h.update(chunk)
                out.write(chunk)
        if h.hexdigest() != file.sha256:
            tmp.unlink(missing_ok=True)
            raise ModelError(
                f"{file.name}: SHA-256 {h.hexdigest()} is not the pinned {file.sha256}"
            )
        tmp.replace(path)
        log.info("model_file_fetched", model=spec.name, file=file.name, bytes=file.size)
    return target


# --- reading the model ---------------------------------------------------------------------------


def _read_safetensors(path: Path) -> Vector:
    """The one tensor of a model2vec safetensors file, as float32 [vocab, dim]."""
    data = path.read_bytes()
    size = int.from_bytes(data[:8], "little")
    header = json.loads(data[8 : 8 + size])
    tensors = {k: v for k, v in header.items() if k != "__metadata__"}
    if len(tensors) != 1:
        raise ModelError(f"{path.name}: expected one tensor, found {sorted(tensors)}")
    (info,) = tensors.values()
    if info["dtype"] != "F32" or len(info["shape"]) != 2:
        raise ModelError(f"{path.name}: expected a 2-D F32 tensor, found {info}")
    start, end = info["data_offsets"]
    rows, dim = info["shape"]
    body = data[8 + size + start : 8 + size + end]
    if len(body) != rows * dim * 4:
        raise ModelError(f"{path.name}: tensor data is truncated")
    return np.frombuffer(body, dtype="<f4").reshape(rows, dim).astype(np.float32)


def _is_punctuation(ch: str) -> bool:
    cp = ord(ch)
    if 33 <= cp <= 47 or 58 <= cp <= 64 or 91 <= cp <= 96 or 123 <= cp <= 126:
        return True
    return unicodedata.category(ch).startswith("P")


def _is_cjk(cp: int) -> bool:
    return (
        0x4E00 <= cp <= 0x9FFF
        or 0x3400 <= cp <= 0x4DBF
        or 0x20000 <= cp <= 0x2A6DF
        or 0x2A700 <= cp <= 0x2CEAF
        or 0xF900 <= cp <= 0xFAFF
        or 0x2F800 <= cp <= 0x2FA1F
    )


def basic_tokens(text: str) -> list[str]:
    """BERT's basic tokenizer as the model was trained with it: control characters dropped,
    CJK characters split, lower-cased, accents stripped, split on whitespace and punctuation."""
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if cp in {0, 0xFFFD}:
            continue
        if ch in "\t\n\r" or unicodedata.category(ch) == "Zs":
            out.append(" ")
        elif unicodedata.category(ch).startswith("C"):
            continue
        elif _is_cjk(cp):
            out.append(f" {ch} ")
        else:
            out.append(ch)
    words: list[str] = []
    for raw in "".join(out).lower().split():
        word = "".join(
            c for c in unicodedata.normalize("NFD", raw) if unicodedata.category(c) != "Mn"
        )
        piece = ""
        for ch in word:
            if _is_punctuation(ch):
                if piece:
                    words.append(piece)
                    piece = ""
                words.append(ch)
            else:
                piece += ch
        if piece:
            words.append(piece)
    return words


@dataclass
class Embedder:
    """``embed(text)``: the normalised mean of the text's word-piece vectors."""

    vectors: Vector
    vocab: dict[str, int]
    name: str
    unk: int
    _cache: dict[str, Vector] = field(default_factory=dict, repr=False)

    @property
    def dim(self) -> int:
        return int(self.vectors.shape[1])

    def pieces(self, text: str) -> list[int]:
        """WordPiece ids, greedy longest match first; a word that can't be split is unknown,
        and unknown pieces are dropped (as model2vec does)."""
        ids: list[int] = []
        for word in basic_tokens(text):
            if len(word) > 100:
                continue
            start = 0
            found: list[int] = []
            while start < len(word):
                end, cur = len(word), None
                while start < end:
                    sub = word[start:end] if start == 0 else "##" + word[start:end]
                    if sub in self.vocab:
                        cur = self.vocab[sub]
                        break
                    end -= 1
                if cur is None:
                    found = []
                    break
                found.append(cur)
                start = end
            ids.extend(i for i in found if i != self.unk)
        return ids

    def embed(self, text: str) -> Vector:
        hit = self._cache.get(text)
        if hit is not None:
            return hit
        vec = self.pool(self.pieces(text))
        if len(self._cache) < 50_000:
            self._cache[text] = vec
        return vec

    def pool(self, ids: list[int], weights: npt.NDArray[np.float32] | None = None) -> Vector:
        """The normalised (weighted) mean of the pieces' vectors; zeros for no pieces."""
        if not ids:
            return np.zeros(self.dim, dtype=np.float32)
        rows = self.vectors[ids]
        if weights is None:
            vec = rows.mean(axis=0)
        else:
            w = weights[ids][:, None]
            vec = (rows * w).sum(axis=0) / max(float(w.sum()), 1e-9)
        norm = float(np.linalg.norm(vec))
        return (vec / norm if norm > 0 else vec).astype(np.float32)


def load(spec: ModelSpec = MODEL, root: Path | None = None) -> Embedder:
    """Load ``spec``, checking every file against its pinned SHA-256 first."""
    where = (root or models_dir()) / spec.name
    for file in spec.files:
        path = where / file.name
        if not path.exists():
            raise ModelError(f"{spec.name} is not installed (run `kasauti models fetch`)")
        digest = _sha256(path)
        if digest != file.sha256:
            raise ModelError(
                f"{spec.name}/{file.name}: SHA-256 {digest} is not the pinned {file.sha256}; "
                "the file was changed, so it is not used"
            )
    vocab_lines = (where / "vocab.txt").read_text(encoding="utf-8").splitlines()
    vocab = {w: i for i, w in enumerate(vocab_lines)}
    vectors = _read_safetensors(where / "model.safetensors")
    if vectors.shape[0] != len(vocab):
        raise ModelError(f"{spec.name}: {vectors.shape[0]} vectors for {len(vocab)} word pieces")
    return Embedder(vectors, vocab, spec.name, vocab.get("[UNK]", -1))


_LOADED: dict[str, Embedder | None] = {}


def shared(spec: ModelSpec = MODEL) -> Embedder | None:
    """The process's embedder, loaded once; ``None`` (and one warning) when the model isn't
    installed or fails its check, so the signals that need it abstain."""
    key = f"{models_dir()}::{spec.name}"
    if key not in _LOADED:
        try:
            _LOADED[key] = load(spec)
        except (ModelError, OSError, ValueError) as e:
            log.warning("model_unavailable", model=spec.name, reason=str(e))
            _LOADED[key] = None
    return _LOADED[key]
