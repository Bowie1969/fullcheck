from __future__ import annotations
import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from .action import Action


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class Evidence:
    """Chain of custody. Every artifact is hashed, timestamped, tied to auth."""

    def __init__(self, engagement_dir: Path, auth_ref: str):
        self.dir = Path(engagement_dir)
        self.auth_ref = auth_ref
        self.raw = self.dir / "raw"
        self.evi = self.dir / "evidence"
        self.raw.mkdir(parents=True, exist_ok=True)
        self.evi.mkdir(parents=True, exist_ok=True)
        self._manifest_lock = threading.Lock()
        self.manifest_path = self.evi / "manifest.json"
        if not self.manifest_path.exists():
            self.manifest_path.write_text(
                json.dumps(
                    {"auth_ref": auth_ref, "created": _now(), "entries": []}, indent=2
                )
            )

    def record(
        self,
        action: Action,
        stdout: bytes,
        stderr: bytes,
        exit_code: int,
        artifact_name: str,
    ) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        stem = f"{ts}_{action.tool}_{artifact_name}"
        raw_path = self.raw / f"{stem}.json"
        blob = {
            "action": action.to_dict(),
            "auth_ref": self.auth_ref,
            "exit_code": exit_code,
            "stdout_sha256": _sha256_bytes(stdout),
            "stderr_sha256": _sha256_bytes(stderr),
            "stdout": stdout.decode(errors="replace"),
            "stderr": stderr.decode(errors="replace"),
        }
        raw_bytes = json.dumps(blob, indent=2).encode()
        raw_path.write_bytes(raw_bytes)
        self._append_manifest(
            {
                "ts": _now(),
                "artifact": str(raw_path.relative_to(self.dir)),
                "sha256": _sha256_bytes(raw_bytes),
                "tool": action.tool,
                "target": action.target,
                "blast_radius": action.blast_radius.value,
                "exit_code": exit_code,
            }
        )
        return raw_path

    def _append_manifest(self, entry: dict[str, Any]) -> None:
        with self._manifest_lock:
            m = json.loads(self.manifest_path.read_text())
            m["entries"].append(entry)
            m["updated"] = _now()
            self.manifest_path.write_text(json.dumps(m, indent=2))
