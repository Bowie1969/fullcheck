"""The autonomy router: given the engagement's mode and a technique, decide
whether an exploit-tier action AUTO-runs or must be GATE'd for human approval.

This decides *only* whether a human must confirm. Whether the action is allowed
at all (scope, engagement ceiling, per-CIDR zone ceiling, rate) is a separate,
non-negotiable check done by the Dispatcher at run/propose time.

Modes (set per engagement in scope.yaml as `autonomy:`):
  * gated      — every exploit-tier action is gated (mirrors external FullCheck).
  * auto_low   — enum auto-runs; CEILING techniques flagged low_risk auto-run;
                 everything else gated.
  * aggressive — every CEILING technique auto-runs (within ceiling); only the
                 structural FLOOR still gates. This is the mode this build ships
                 configured for.

FLOOR always gates, in every mode — that is the hard floor the dial can't lower.
"""

from __future__ import annotations

from enum import Enum

from ..action import Action, BlastRadius
from .catalog import GateClass, InternalExploit

VALID_MODES = ("gated", "auto_low", "aggressive")


class Decision(str, Enum):
    AUTO = "auto"   # run now — dispatcher-checked and evidence-logged, no confirm
    GATE = "gate"   # park for a single human ApprovalGate confirmation


def decide(mode: str, exploit: InternalExploit, action: Action) -> Decision:
    # The hard floor: disruptive / irreversible / lockout-risk / post-exploit.
    if exploit.gate_class is GateClass.FLOOR:
        return Decision.GATE

    br = action.blast_radius
    if mode == "aggressive":
        return Decision.AUTO  # all CEILING-class auto-runs (Dispatcher enforces ceiling)

    if mode == "auto_low":
        if br in (BlastRadius.PASSIVE, BlastRadius.PROBE, BlastRadius.SCAN):
            return Decision.AUTO
        return Decision.AUTO if exploit.low_risk else Decision.GATE

    # "gated" — and any unrecognised mode falls through here (fail safe).
    if br in (BlastRadius.EXPLOIT, BlastRadius.POST_EXPLOIT):
        return Decision.GATE
    return Decision.AUTO
