from __future__ import annotations
import fnmatch
import ipaddress
import threading
import time
import yaml
from collections import defaultdict, deque
from pathlib import Path
from typing import Any
from .action import Action, BlastRadius, exceeds


class ScopeViolation(Exception):
    pass


class CeilingExceeded(Exception):
    pass


class RateLimited(Exception):
    pass


class Dispatcher:
    """Every tool call passes through here. Non-negotiable."""

    def __init__(self, scope_path: Path):
        self.scope_path = Path(scope_path)
        self._load()
        self._recent: dict[str, deque[float]] = defaultdict(deque)
        self._rate_lock = threading.Lock()

    def _load(self) -> None:
        if not self.scope_path.exists():
            raise FileNotFoundError(
                f"scope.yaml not found at {self.scope_path}. "
                f"Copy scope.yaml.example and add your engagement."
            )
        self.cfg = yaml.safe_load(self.scope_path.read_text())
        self.engagements = self.cfg.get("engagements", {}) or {}
        self.rate = self.cfg.get("rate_limits", {}) or {}

    def _in_scope(self, engagement: str, target: str) -> bool:
        eng = self.engagements.get(engagement)
        if not eng:
            return False
        for oos in eng.get("out_of_scope", []) or []:
            if _target_matches(target, oos):
                return False
        for allowed in eng.get("scope", []) or []:
            if _target_matches(target, allowed):
                return True
        return False

    def _rate_ok(self, host: str) -> bool:
        rps = int(self.rate.get("requests_per_second_per_host", 5))
        now = time.time()
        with self._rate_lock:
            dq = self._recent[host]
            while dq and now - dq[0] > 1.0:
                dq.popleft()
            if len(dq) >= rps:
                return False
            dq.append(now)
            return True

    def _effective_ceiling(self, eng: dict, target: str) -> BlastRadius:
        """Engagement ceiling, tightened by the most restrictive matching
        per-CIDR `zone_ceilings` override (optional; absent => engagement ceiling).

        Lets a fragile OT/SCADA or DC subnet be capped at e.g. `probe` while the
        engagement as a whole is allowed to `exploit`. Backward compatible: with
        no `zone_ceilings` key the result is exactly the engagement ceiling, so
        existing (external) engagements are unaffected.
        """
        ceiling = BlastRadius(eng.get("ceiling", "probe"))
        for zone in eng.get("zone_ceilings", []) or []:
            cidr = zone.get("cidr", "")
            if cidr and _target_matches(target, cidr):
                zc = BlastRadius(zone.get("ceiling", "passive"))
                if exceeds(ceiling, zc):  # zc is more restrictive than current
                    ceiling = zc
        return ceiling

    def check(self, action: Action) -> None:
        """Raise if the action is not allowed. No return value on success."""
        if not action.engagement:
            raise ScopeViolation("action has no engagement id")
        if action.engagement not in self.engagements:
            raise ScopeViolation(f"unknown engagement: {action.engagement}")
        eng = self.engagements[action.engagement]
        ceiling = self._effective_ceiling(eng, action.target)
        if exceeds(action.blast_radius, ceiling):
            raise CeilingExceeded(
                f"{action.blast_radius.value} exceeds engagement ceiling "
                f"{ceiling.value} for {action.engagement}"
            )
        if not self._in_scope(action.engagement, action.target):
            raise ScopeViolation(
                f"target {action.target} not in scope for {action.engagement}"
            )
        if not self._rate_ok(action.target):
            raise RateLimited(f"rate limit hit for {action.target}")


def _target_matches(target: str, pattern: str) -> bool:
    # CIDR
    try:
        net = ipaddress.ip_network(pattern, strict=False)
        try:
            return ipaddress.ip_address(target) in net
        except ValueError:
            return False
    except ValueError:
        pass
    # glob (handles *.domain)
    return fnmatch.fnmatch(target.lower(), pattern.lower())
