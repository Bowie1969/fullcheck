"""Per-exploit human-in-the-loop approval gate.

Design principle (same as lab-asset-suite/cmc/approval.py, made synchronous and
cross-process for FullCheck's CLI + worker-pool model):

    An exploit-tier action NEVER executes on a worker's or the LLM's decision
    alone. When a worker proposes an exploit, the gate parks it as a PENDING
    record and mints an approval token. The command runs only after a human
    issues an explicit `confirm` decision carrying that exact token, and only
    once (single-use), and only before it expires.

The token cannot be minted by the LLM or a worker — only `propose()` mints one,
and only a matching human `decide(confirm=True)` releases it. `consume()` at
execution time re-checks status/expiry and burns the token so the same approval
can never run twice.

State is persisted per-engagement so the worker pool (proposing) and a separate
`fullcheck approve` invocation (deciding) share one queue. Writes are guarded by
a portable exclusive lockfile; every transition is also appended to an
append-only audit log for chain of custody, mirroring evidence.py.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from .action import Action, BlastRadius

DEFAULT_TTL_SECONDS = 900.0  # 15 min: a human reviewing a queue, not a live loop


class ExploitStatus(str, Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    DENIED = "denied"
    EXPIRED = "expired"
    CONSUMED = "consumed"  # confirmed AND executed — terminal, cannot re-run


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class PendingExploit:
    token: str
    engagement: str
    target: str
    exploit_id: str
    command: list[str]
    blast_radius: str
    reason: str
    proposed_by: str
    created: float
    ttl: float
    status: str = ExploitStatus.PENDING.value
    decided_by: str = ""
    decided_at: str = ""
    consumed_at: str = ""

    @property
    def expires_at(self) -> float:
        return self.created + self.ttl

    def is_expired(self, now: float | None = None) -> bool:
        return (now or time.time()) >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ApprovalError(Exception):
    pass


class _FileLock:
    """Minimal portable exclusive lock via O_CREAT|O_EXCL (atomic on Win + POSIX)."""

    def __init__(self, path: Path, timeout: float = 10.0, stale: float = 60.0):
        self.path = Path(str(path) + ".lock")
        self.timeout = timeout
        self.stale = stale
        self._fd: int | None = None

    def __enter__(self) -> "_FileLock":
        deadline = time.time() + self.timeout
        while True:
            try:
                self._fd = os.open(
                    self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY
                )
                os.write(self._fd, str(os.getpid()).encode())
                return self
            except FileExistsError:
                # break a stale lock left by a crashed process
                try:
                    if time.time() - self.path.stat().st_mtime > self.stale:
                        self.path.unlink(missing_ok=True)
                        continue
                except FileNotFoundError:
                    continue
                if time.time() >= deadline:
                    raise ApprovalError(f"could not acquire lock {self.path}")
                time.sleep(0.05)

    def __exit__(self, *exc: object) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        self.path.unlink(missing_ok=True)


class ApprovalGate:
    """Issues exploit-approval tokens and resolves human decisions.

    Backed by two files under the engagement dir:
      exploit_queue.json   — {token: record}, the live queryable state
      exploit_audit.jsonl  — append-only transition log (chain of custody)
    """

    def __init__(self, engagement_dir: Path, ttl_seconds: float = DEFAULT_TTL_SECONDS):
        self.dir = Path(engagement_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._ttl = ttl_seconds
        self.queue_path = self.dir / "exploit_queue.json"
        self.audit_path = self.dir / "exploit_audit.jsonl"
        self._lock = _FileLock(self.queue_path)

    # ---- persistence -------------------------------------------------------

    def _read(self) -> dict[str, dict]:
        if not self.queue_path.exists():
            return {}
        try:
            return json.loads(self.queue_path.read_text())
        except json.JSONDecodeError:
            return {}

    def _write(self, data: dict[str, dict]) -> None:
        tmp = self.queue_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.replace(self.queue_path)

    def _audit(self, event: str, rec: dict) -> None:
        line = {
            "ts": _now_iso(),
            "event": event,
            "token": rec.get("token"),
            "engagement": rec.get("engagement"),
            "target": rec.get("target"),
            "exploit_id": rec.get("exploit_id"),
            "blast_radius": rec.get("blast_radius"),
            "status": rec.get("status"),
            "decided_by": rec.get("decided_by"),
        }
        with self.audit_path.open("a") as fh:
            fh.write(json.dumps(line) + "\n")

    @staticmethod
    def _refresh_expiry(rec: dict) -> dict:
        """Lazily flip a PENDING record to EXPIRED once its TTL has passed."""
        if rec["status"] == ExploitStatus.PENDING.value:
            if time.time() >= rec["created"] + rec["ttl"]:
                rec["status"] = ExploitStatus.EXPIRED.value
        return rec

    # ---- API ---------------------------------------------------------------

    def propose(
        self,
        action: Action,
        command: list[str],
        exploit_id: str,
        proposed_by: str,
    ) -> PendingExploit:
        """Park an exploit action and return its pending record. Does NOT run it.

        Raises if the action is not exploit-tier — read-only work must never
        flow through the approval queue.
        """
        if action.blast_radius not in (BlastRadius.EXPLOIT, BlastRadius.POST_EXPLOIT):
            raise ApprovalError(
                f"propose() requires an exploit-tier action, got "
                f"{action.blast_radius.value}"
            )
        pending = PendingExploit(
            token=secrets.token_hex(16),
            engagement=action.engagement,
            target=action.target,
            exploit_id=exploit_id,
            command=list(command),
            blast_radius=action.blast_radius.value,
            reason=action.reason,
            proposed_by=proposed_by,
            created=time.time(),
            ttl=self._ttl,
        )
        with self._lock:
            data = self._read()
            data[pending.token] = pending.to_dict()
            self._write(data)
            self._audit("proposed", pending.to_dict())
        return pending

    def decide(self, token: str, confirm: bool, decided_by: str) -> PendingExploit:
        """Apply a human decision. Returns the updated record.

        Raises ApprovalError if the token is unknown, already decided/consumed,
        or expired — the caller must tell the operator the approval is no longer
        actionable rather than silently doing nothing.
        """
        if not decided_by:
            raise ApprovalError("a human identity (decided_by) is required to decide")
        with self._lock:
            data = self._read()
            raw = data.get(token)
            if raw is None:
                raise ApprovalError(f"unknown approval token: {token}")
            raw = self._refresh_expiry(raw)
            status = raw["status"]
            if status != ExploitStatus.PENDING.value:
                self._write(data)  # persist any lazy expiry flip
                raise ApprovalError(
                    f"token {token} is {status}, not pending — cannot decide"
                )
            raw["status"] = (
                ExploitStatus.CONFIRMED.value if confirm else ExploitStatus.DENIED.value
            )
            raw["decided_by"] = decided_by
            raw["decided_at"] = _now_iso()
            data[token] = raw
            self._write(data)
            self._audit("confirmed" if confirm else "denied", raw)
            return PendingExploit(**raw)

    def consume(self, token: str) -> PendingExploit:
        """Burn a CONFIRMED token for execution. Single-use and terminal.

        Returns the record only if it is confirmed, unexpired, and unused;
        otherwise raises. After this call the token is CONSUMED forever.
        """
        with self._lock:
            data = self._read()
            raw = data.get(token)
            if raw is None:
                raise ApprovalError(f"unknown approval token: {token}")
            if raw["status"] == ExploitStatus.CONSUMED.value:
                raise ApprovalError(f"token {token} already consumed — refusing re-run")
            if raw["status"] != ExploitStatus.CONFIRMED.value:
                raise ApprovalError(
                    f"token {token} is {raw['status']}, not confirmed — cannot execute"
                )
            # A confirmed approval that sat past its TTL is stale; require re-approval.
            if time.time() >= raw["created"] + raw["ttl"]:
                raw["status"] = ExploitStatus.EXPIRED.value
                data[token] = raw
                self._write(data)
                self._audit("expired", raw)
                raise ApprovalError(f"token {token} expired before execution")
            raw["status"] = ExploitStatus.CONSUMED.value
            raw["consumed_at"] = _now_iso()
            data[token] = raw
            self._write(data)
            self._audit("consumed", raw)
            return PendingExploit(**raw)

    def pending(self) -> list[PendingExploit]:
        """All still-actionable PENDING records (lazily expiring stale ones)."""
        with self._lock:
            data = self._read()
            changed = False
            out: list[PendingExploit] = []
            for token, raw in data.items():
                before = raw["status"]
                raw = self._refresh_expiry(raw)
                if raw["status"] != before:
                    changed = True
                    self._audit("expired", raw)
                if raw["status"] == ExploitStatus.PENDING.value:
                    out.append(PendingExploit(**raw))
            if changed:
                self._write(data)
        out.sort(key=lambda p: p.created)
        return out

    def get(self, token: str) -> PendingExploit | None:
        raw = self._read().get(token)
        return PendingExploit(**raw) if raw else None
