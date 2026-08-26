"""Parallel worker pool for the recon/scan fan-out (the "swarm").

Concurrency belongs to discovery, not exploitation. This pool runs the
passive/probe/scan-tier pipeline across many targets at once; exploitation
never runs here — it goes through the ApprovalGate one human confirmation at a
time (see approval.py / tools/exploit.py).

Two independent bounds keep the fan-out authorized-and-polite:
  * `workers` caps total concurrency (threads across the whole matrix), and
  * the Dispatcher's per-host rate limit (thread-safe) caps hits on any single
    host — so 50 workers spread across many subdomains, never 50 onto one box.

A worker whose action the Dispatcher denies (out of scope, over ceiling, rate
limited) is recorded and skipped; the pool never bypasses the gate to keep busy.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .dispatcher import Dispatcher, ScopeViolation, CeilingExceeded, RateLimited
from .evidence import Evidence
from .tools.base import Tool
from .tools.recon import RECON_PIPELINE

DEFAULT_WORKERS = 10
MAX_WORKERS = 50


@dataclass
class SwarmSummary:
    ran: list[dict] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"ran": self.ran, "skipped": self.skipped, "errors": self.errors}


def _run_one(
    tool: Tool,
    target: str,
    engagement: str,
    dispatcher: Dispatcher,
    evidence: Evidence,
) -> tuple[str, dict]:
    """Execute one (tool, target). Returns a (bucket, record) pair for the summary."""
    try:
        res = tool.run(
            target=target,
            engagement=engagement,
            dispatcher=dispatcher,
            evidence=evidence,
        )
        return "ran", {"tool": tool.name, "target": target, "exit": res.exit_code}
    except (ScopeViolation, CeilingExceeded, RateLimited) as e:
        return "skipped", {"tool": tool.name, "target": target, "why": str(e)}
    except Exception as e:  # noqa: BLE001 - one worker failing must not sink the pool
        return "errors", {"tool": tool.name, "target": target, "error": str(e)}


def run_swarm(
    engagement: str,
    targets: list[str],
    engagement_dir: Path,
    auth_ref: str,
    scope_path: Path,
    workers: int = DEFAULT_WORKERS,
    pipeline: list[Tool] | None = None,
    log: Callable[[str], None] = print,
) -> dict[str, Any]:
    """Fan the recon/scan pipeline out across targets on a bounded thread pool.

    Every unit of work still passes through the one shared Dispatcher (scope +
    ceiling + thread-safe rate limit) and the one shared Evidence chain.
    """
    pipeline = pipeline if pipeline is not None else RECON_PIPELINE
    dispatcher = Dispatcher(scope_path)
    # scope.yaml's rate_limits.max_workers is the authoritative cap (default 50).
    hard_cap = int(dispatcher.rate.get("max_workers", MAX_WORKERS) or MAX_WORKERS)
    hard_cap = max(1, min(hard_cap, MAX_WORKERS))
    workers = max(1, min(int(workers), hard_cap))
    evidence = Evidence(engagement_dir, auth_ref)
    summary = SwarmSummary()

    # Build the work matrix, skipping tools whose binary is absent (once, up front).
    matrix: list[tuple[Tool, str]] = []
    for tool in pipeline:
        if not tool.available():
            log(f"  [skip] {tool.name}: binary not on PATH")
            summary.skipped.append({"tool": tool.name, "why": "not installed"})
            continue
        for target in targets:
            matrix.append((tool, target))

    if not matrix:
        return summary.as_dict()

    log(f"  dispatching {len(matrix)} tasks across {workers} workers")
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {
            pool.submit(_run_one, tool, target, engagement, dispatcher, evidence): (
                tool.name,
                target,
            )
            for tool, target in matrix
        }
        for fut in as_completed(futs):
            bucket, record = fut.result()
            getattr(summary, bucket).append(record)
            tag = {"ran": "ok", "skipped": "DENY", "errors": "err"}[bucket]
            detail = record.get("why") or record.get("error") or f"exit {record.get('exit')}"
            log(f"  [{tag:>4}] {record['tool']} -> {record['target']}: {detail}")

    return summary.as_dict()
