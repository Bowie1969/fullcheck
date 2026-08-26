from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any, Callable, Optional

# Default: bge-small (384-dim) — fast, fits comfortably in ~6GB VRAM, good
# enough for CVE description matching. Override with FULLCHECK_EMBED_MODEL.
DEFAULT_MODEL = os.environ.get("FULLCHECK_EMBED_MODEL", "BAAI/bge-small-en-v1.5")


def st_available() -> bool:
    try:
        import sentence_transformers  # noqa: F401
        import numpy  # noqa: F401
        return True
    except Exception:
        return False


def cuda_available() -> bool:
    try:
        import torch
        return bool(torch.cuda.is_available())
    except Exception:
        return False


class EmbeddingIndex:
    """Brute-force cosine search over CVE description vectors.

    Vectors persist as sidecars next to the SQLite cache:
      cache.vectors.npy  (float32 [N, dim], L2-normalized)
      cache.ids.json     (list[str] of CVE ids, row-aligned)

    `encode_fn` is injectable so the cosine logic is testable without a model.
    In production it is None and a sentence-transformers model is loaded lazily.
    """

    def __init__(
        self,
        db_path: Path,
        model_name: str = DEFAULT_MODEL,
        encode_fn: Optional[Callable[[list[str]], Any]] = None,
        device: Optional[str] = None,
    ):
        self.db_path = Path(db_path)
        self.model_name = model_name
        self.vec_path = self.db_path.with_suffix(".vectors.npy")
        self.ids_path = self.db_path.with_suffix(".ids.json")
        self._encode_fn = encode_fn
        self._device = device
        self._model = None
        self._vectors = None
        self._ids: list[str] = []

    # --- model / encode ---------------------------------------------------
    def _lazy_model(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            dev = self._device or ("cuda" if cuda_available() else "cpu")
            self._model = SentenceTransformer(self.model_name, device=dev)
        return self._model

    def _encode(self, texts: list[str]):
        import numpy as np
        if self._encode_fn is not None:
            arr = np.asarray(self._encode_fn(texts), dtype="float32")
        else:
            model = self._lazy_model()
            arr = np.asarray(
                model.encode(texts, batch_size=256, show_progress_bar=False),
                dtype="float32",
            )
        # L2-normalize so dot product == cosine similarity
        norms = np.linalg.norm(arr, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return arr / norms

    # --- build / load -----------------------------------------------------
    def build(self, rows: list[tuple[str, str]], batch: int = 512) -> int:
        """rows: list of (cve_id, description). Returns count embedded."""
        import numpy as np
        ids: list[str] = []
        vecs = []
        buf_ids, buf_txt = [], []

        def flush():
            if buf_txt:
                vecs.append(self._encode(buf_txt))
                ids.extend(buf_ids)
                buf_ids.clear()
                buf_txt.clear()

        for cid, desc in rows:
            if not desc:
                continue
            buf_ids.append(cid)
            buf_txt.append(desc[:1000])
            if len(buf_txt) >= batch:
                flush()
        flush()
        if not vecs:
            return 0
        mat = np.vstack(vecs).astype("float32")
        np.save(self.vec_path, mat)
        self.ids_path.write_text(json.dumps(ids))
        self._vectors, self._ids = mat, ids
        return len(ids)

    def _ensure_loaded(self) -> bool:
        import numpy as np
        if self._vectors is not None:
            return True
        if self.vec_path.exists() and self.ids_path.exists():
            self._vectors = np.load(self.vec_path)
            self._ids = json.loads(self.ids_path.read_text())
            return True
        return False

    def exists(self) -> bool:
        return self.vec_path.exists() and self.ids_path.exists()

    # --- query ------------------------------------------------------------
    def search(self, query: str, top_k: int = 10) -> list[tuple[str, float]]:
        import numpy as np
        if not self._ensure_loaded():
            return []
        q = self._encode([query])[0]
        sims = self._vectors @ q
        k = min(top_k, len(self._ids))
        idx = np.argpartition(-sims, k - 1)[:k]
        idx = idx[np.argsort(-sims[idx])]
        return [(self._ids[i], float(sims[i])) for i in idx]
