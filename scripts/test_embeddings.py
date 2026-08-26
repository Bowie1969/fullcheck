"""Embedding-path test using a deterministic fake encoder (no torch/model needed).
Run: python scripts/test_embeddings.py
"""
from __future__ import annotations
import sys, tempfile, hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import numpy as np  # noqa: E402
from fullcheck.intel.embeddings import EmbeddingIndex  # noqa: E402
from fullcheck.intel.cve_cache import CveCache  # noqa: E402

PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS  {name}")
    else:
        FAIL += 1; print(f"  FAIL  {name}")


def fake_encode(texts):
    """Deterministic pseudo-embedding: hash words into a 32-dim bag-of-words.
    Similar text -> similar vectors, good enough to test ranking."""
    dim = 32
    out = np.zeros((len(texts), dim), dtype="float32")
    for i, t in enumerate(texts):
        for w in t.lower().split():
            h = int(hashlib.md5(w.encode()).hexdigest(), 16) % dim
            out[i, h] += 1.0
    return out


def main():
    tmp = Path(tempfile.mkdtemp(prefix="fc_embed_"))
    db = tmp / "cache.db"

    # seed a CVE cache
    cache = CveCache(db, use_embeddings=False)
    seed = [
        ("CVE-2021-41773", "Apache HTTP Server 2.4.49 path traversal directory"),
        ("CVE-2021-44228", "Apache Log4j2 JNDI remote code execution Log4Shell"),
        ("CVE-2017-5638", "Apache Struts2 remote code execution content type"),
        ("CVE-2019-11043", "PHP FPM nginx remote code execution buffer"),
    ]
    for cid, desc in seed:
        cache.conn.execute("INSERT OR REPLACE INTO cve VALUES (?,?,?,?,?)",
                           (cid, "2021", 9.8, "CRITICAL", desc))
    cache.conn.execute("INSERT INTO cve_fts(cve_fts) VALUES('rebuild')")
    cache.conn.commit()

    print("[fallback: no vector index -> FTS keyword]")
    check("semantic disabled before build", not cache.semantic_enabled())
    r = cache.search("Apache path traversal")
    check("FTS returns 41773", any("41773" in x["id"] for x in r))

    print("[build vector index with fake encoder]")
    idx = EmbeddingIndex(db, encode_fn=fake_encode)
    n = idx.build(seed)
    check("built 4 vectors", n == 4)
    check("vectors.npy persisted", idx.vec_path.exists())
    check("ids.json persisted", idx.ids_path.exists())

    print("[semantic search ranks by meaning]")
    hits = idx.search("remote code execution JNDI", top_k=3)
    ids = [h[0] for h in hits]
    check("Log4Shell top hit for JNDI RCE query", ids[0] == "CVE-2021-44228")
    check("scores normalized <= 1.0", all(s <= 1.0001 for _, s in hits))

    print("[reload from disk]")
    idx2 = EmbeddingIndex(db, encode_fn=fake_encode)
    check("index exists() true", idx2.exists())
    hits2 = idx2.search("path traversal directory", top_k=2)
    check("reloaded search finds traversal CVE", hits2[0][0] == "CVE-2021-41773")

    print(f"\n{'='*40}\n  {PASS} passed, {FAIL} failed\n{'='*40}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
