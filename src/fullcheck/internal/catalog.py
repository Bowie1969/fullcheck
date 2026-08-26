"""Exploit technique catalog with a *structural* impact class.

The single most important idea, borrowed straight from lab-asset-suite's
security model: **impact is defined by the catalog, not by the LLM and not by
the autonomy dial.** Each technique is either:

  * FLOOR   — always runs through the human ApprovalGate, even when the
              engagement's autonomy mode is `aggressive`. This is the hard floor
              under "ceiling-only aggressive": password spray (account lockout),
              live MITM/relay/poisoning, coercion, host-crash-capable memory
              exploits, and every post-exploitation action (lateral movement,
              credential dumping, persistence).
  * CEILING — reversible / non-disruptive. May auto-run when the Dispatcher
              says it's within the engagement (and per-CIDR) ceiling AND the
              autonomy mode allows it (see autonomy.py).

`InternalExploit.run_auto` re-asserts the FLOOR check itself, so even a bug in
the routing layer can never auto-fire a FLOOR technique without a human token.
The default class is FLOOR (default-deny): a technique is only auto-runnable if
someone deliberately classified it CEILING.
"""

from __future__ import annotations

import subprocess
from enum import Enum

from ..action import BlastRadius
from ..approval import ApprovalError
from ..dispatcher import Dispatcher
from ..evidence import Evidence
from ..tools.exploit import Exploit, ExploitResult


class GateClass(str, Enum):
    FLOOR = "floor"      # always human-gated
    CEILING = "ceiling"  # may auto-run within ceiling when autonomy allows


def _safe(target: str) -> str:
    return target.replace("/", "_").replace(":", "_").replace("\\", "_")


class InternalExploit(Exploit):
    """An exploit-tier technique carrying a structural gate class.

    Reuses the external Exploit base verbatim for the gated path
    (propose/execute through the ApprovalGate). Adds `run_auto` for the
    CEILING-class auto path the autonomy engine may clear — with a defensive
    FLOOR re-check so the auto path can never be tricked into running a
    disruptive/irreversible technique.
    """

    gate_class: GateClass = GateClass.FLOOR   # default-deny
    low_risk: bool = False                    # eligible for `auto_low` mode
    param_hint: str = ""                      # human/LLM hint: what params build_cmd needs
                                              # (metadata only — never affects gating)

    def run_auto(
        self,
        target: str,
        engagement: str,
        dispatcher: Dispatcher,
        evidence: Evidence,
        params: dict | None = None,
        timeout: int = 900,
        owned_lab: bool = False,
    ) -> ExploitResult:
        """Execute a technique WITHOUT a human token.

        Only ever called after autonomy.decide() returns AUTO. Still passes the
        Dispatcher (scope + engagement/zone ceiling + rate) and still writes the
        evidence chain — "no per-action confirm" is not "no controls".

        The FLOOR re-check is the defence-in-depth backstop: a FLOOR technique
        (incl. all post-exploitation) can only auto-run when `owned_lab` is True,
        i.e. the `auto_lab` mode on an attested owned lab (autonomy.is_owned_lab).
        The default `owned_lab=False` keeps every other path fail-closed, so a
        routing bug still can't auto-fire a FLOOR technique off the lab.
        """
        if self.gate_class is GateClass.FLOOR and not owned_lab:
            raise ApprovalError(
                f"{self.name} is FLOOR-class — refusing to auto-run without "
                f"human approval (use propose/approve/run instead)"
            )
        params = params or {}
        action = self._action(target, engagement, params)
        dispatcher.check(action)  # scope + ceiling + zone (raises if not allowed)
        cmd = list(self.build_cmd(target, params))
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
        artifact = evidence.record(
            action=action,
            stdout=proc.stdout,
            stderr=proc.stderr,
            exit_code=proc.returncode,
            artifact_name=f"auto_{self.name}_{_safe(target)}",
        )
        return ExploitResult(
            action=action,
            token="",  # no token — auto path
            exploit_id=self.name,
            stdout=proc.stdout,
            stderr=proc.stderr,
            exit_code=proc.returncode,
            artifact_path=str(artifact),
        )


# ---- registry ---------------------------------------------------------------

CATALOG: dict[str, type[InternalExploit]] = {}


def register(cls: type[InternalExploit]) -> type[InternalExploit]:
    """Class decorator: add a technique to the catalog keyed by its `name`."""
    if not cls.name:
        raise ValueError(f"{cls.__name__} must set a non-empty name to register")
    CATALOG[cls.name] = cls
    return cls


def get(name: str) -> InternalExploit:
    """Instantiate a catalog technique by name (raises KeyError if unknown)."""
    if name not in CATALOG:
        known = ", ".join(sorted(CATALOG)) or "(none loaded)"
        raise KeyError(f"unknown technique {name!r}; known: {known}")
    return CATALOG[name]()
