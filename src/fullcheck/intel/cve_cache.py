from __future__ import annotations
import json
import os
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

# NVD retired the legacy JSON 1.1 data feeds (403 now). Use the 2.0 REST API.
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE = 2000        # max resultsPerPage allowed by the API
NVD_WINDOW_DAYS = 120  # max pub date range per request allowed by the API


class CveCache:
    """Local SQLite cache of CVEs.

    Search resolves in this order:
      1. Semantic (embedding) search, if a vector index exists AND
         sentence-transformers is importable.
      2. FTS5 keyword search (always available, no deps, no GPU).
    """

    def __init__(self, db_path: Path, use_embeddings: bool = True):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self._init_schema()
        self._embed_index = None
        if use_embeddings:
            self._maybe_attach_embeddings()

    def _maybe_attach_embeddings(self) -> None:
        from .embeddings import EmbeddingIndex, st_available
        idx = EmbeddingIndex(self.db_path)
        if idx.exists() and st_available():
            self._embed_index = idx

    def semantic_enabled(self) -> bool:
        return self._embed_index is not None

    def _init_schema(self) -> None:
        c = self.conn
        c.execute(
            """CREATE TABLE IF NOT EXISTS cve (
                id TEXT PRIMARY KEY,
                published TEXT,
                cvss REAL,
                severity TEXT,
                description TEXT
            )"""
        )
        c.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts "
            "USING fts5(id, description, content='cve', content_rowid='rowid')"
        )
        c.commit()

    def load_year(self, year: int, log: Callable[[str], None] = lambda m: None) -> int:
        """Ingest all CVEs published in `year` via the NVD 2.0 REST API.

        The API caps pub-date ranges at 120 days and pages at 2000 results, so
        we walk the year in windows and paginate each. Honors NVD_API_KEY (env)
        for the higher rate limit; sleeps to respect the published limits.
        """
        api_key = os.environ.get("NVD_API_KEY", "")
        # Without a key: 5 req / 30s -> ~6s spacing. With a key: 50 / 30s -> ~0.7s.
        delay = 0.7 if api_key else 6.5
        n = 0
        start = datetime(year, 1, 1)
        end = datetime(year, 12, 31, 23, 59, 59)
        win_start = start
        while win_start <= end:
            win_end = min(win_start + timedelta(days=NVD_WINDOW_DAYS - 1), end)
            n += self._load_window(win_start, win_end, api_key, delay, log)
            win_start = win_end + timedelta(seconds=1)
        self.conn.execute("INSERT INTO cve_fts(cve_fts) VALUES('rebuild')")
        self.conn.commit()
        # A vector index is a snapshot of descriptions. Do not let searches use
        # it after the underlying CVE corpus has changed; it must be rebuilt.
        self._invalidate_embeddings()
        return n

    def _load_window(self, d0, d1, api_key, delay, log) -> int:
        idx, total, n = 0, None, 0
        while total is None or idx < total:
            params = {
                "pubStartDate": d0.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": d1.strftime("%Y-%m-%dT%H:%M:%S.999"),
                "resultsPerPage": NVD_PAGE,
                "startIndex": idx,
            }
            data = self._nvd_get(params, api_key)
            total = data.get("totalResults", 0)
            vulns = data.get("vulnerabilities", [])
            for item in vulns:
                cve = item.get("cve", {})
                cid = cve.get("id")
                if not cid:
                    continue
                desc = next(
                    (x["value"] for x in cve.get("descriptions", [])
                     if x.get("lang") == "en"),
                    "",
                )
                cvss, sev = _extract_cvss(cve)
                self.conn.execute(
                    "INSERT OR REPLACE INTO cve VALUES (?,?,?,?,?)",
                    (cid, cve.get("published", ""), cvss, sev, desc),
                )
                n += 1
            self.conn.commit()
            got = len(vulns)
            log(f"    {d0:%Y-%m-%d}..{d1:%Y-%m-%d}  {idx + got}/{total}")
            if got == 0:
                break
            idx += got
            if total and idx < total:
                time.sleep(delay)
        return n

    def _nvd_get(self, params: dict, api_key: str, retries: int = 4) -> dict:
        url = NVD_API + "?" + urllib.parse.urlencode(params)
        headers = {"User-Agent": "fullcheck/0.1"}
        if api_key:
            headers["apiKey"] = api_key
        backoff = 8.0
        for attempt in range(retries):
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=90) as r:
                    return json.load(r)
            except urllib.error.HTTPError as e:
                if e.code in (403, 429, 503) and attempt < retries - 1:
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                raise
            except (urllib.error.URLError, TimeoutError):
                if attempt < retries - 1:
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                raise
        return {}

    def _invalidate_embeddings(self) -> None:
        from .embeddings import EmbeddingIndex

        idx = EmbeddingIndex(self.db_path)
        for path in (idx.vec_path, idx.ids_path):
            path.unlink(missing_ok=True)
        self._embed_index = None

    def build_embeddings(self, log=lambda m: None) -> int:
        """Embed every CVE description into a vector index (needs a GPU-ish box
        and sentence-transformers). Safe no-op-with-message if unavailable."""
        from .embeddings import EmbeddingIndex, st_available, cuda_available
        if not st_available():
            log("sentence-transformers not installed; run: pip install -e '.[embed]'")
            return 0
        log(f"CUDA: {'yes' if cuda_available() else 'no (CPU, slower)'}")
        rows = self.conn.execute("SELECT id, description FROM cve").fetchall()
        idx = EmbeddingIndex(self.db_path)
        n = idx.build([(r[0], r[1]) for r in rows])
        self._embed_index = idx if n else None
        return n

    def _rows_by_ids(self, ids: list[str]) -> dict[str, dict[str, Any]]:
        if not ids:
            return {}
        qs = ",".join("?" * len(ids))
        rows = self.conn.execute(
            f"SELECT id, cvss, severity, description FROM cve WHERE id IN ({qs})",
            ids,
        ).fetchall()
        return {
            r[0]: {"id": r[0], "cvss": r[1], "severity": r[2], "description": r[3]}
            for r in rows
        }

    def _semantic_search(self, text: str, limit: int) -> list[dict[str, Any]]:
        hits = self._embed_index.search(text, top_k=limit)
        by_id = self._rows_by_ids([cid for cid, _ in hits])
        out = []
        for cid, score in hits:
            row = by_id.get(cid)
            if row:
                row = dict(row)
                row["score"] = round(score, 4)
                out.append(row)
        return out

    def _fts_search(self, text: str, limit: int) -> list[dict[str, Any]]:
        # Sanitize into safe FTS5: strip each token to alnum, wrap as a quoted
        # phrase, OR them together. Quoting avoids FTS5 syntax errors on tokens
        # containing '.' or '-' (e.g. "2.4.49"), which are otherwise operators.
        terms = []
        for tok in text.replace(".", " ").replace("-", " ").split():
            clean = "".join(ch for ch in tok if ch.isalnum())
            if clean:
                terms.append(f'"{clean}"')
        if not terms:
            return []
        q = " OR ".join(terms)
        rows = self.conn.execute(
            """SELECT c.id, c.cvss, c.severity, c.description
               FROM cve_fts f JOIN cve c ON c.id = f.id
               WHERE cve_fts MATCH ? ORDER BY c.cvss DESC LIMIT ?""",
            (q, limit),
        ).fetchall()
        return [
            {"id": r[0], "cvss": r[1], "severity": r[2], "description": r[3]}
            for r in rows
        ]

    def search(self, text: str, limit: int = 10) -> list[dict[str, Any]]:
        if self._embed_index is not None:
            try:
                res = self._semantic_search(text, limit)
                if res:
                    return res
            except Exception:
                pass  # fall through to keyword search on any embedding error
        return self._fts_search(text, limit)

    def cves_for_tech(self, tech: str, version: str = "") -> list[dict[str, Any]]:
        return self.search(f"{tech} {version}".strip())


def _extract_cvss(cve: dict) -> tuple[float, str]:
    """Read CVSS from an NVD 2.0 `cve.metrics` block. Prefers v3.1 > v3.0 > v2.
    In 2.0, base severity for v3 lives in cvssData.baseSeverity; for v2 it sits
    on the metric object (cvssData has no baseSeverity)."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            cd = entries[0].get("cvssData", {})
            return (
                float(cd.get("baseScore", 0.0)),
                cd.get("baseSeverity", "UNKNOWN"),
            )
    v2 = metrics.get("cvssMetricV2") or []
    if v2:
        cd = v2[0].get("cvssData", {})
        sev = v2[0].get("baseSeverity", "UNKNOWN")
        return float(cd.get("baseScore", 0.0)), sev
    return 0.0, "UNKNOWN"
