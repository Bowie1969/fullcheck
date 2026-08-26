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
  * auto_lab   — FULLY autonomous: even FLOOR (incl. post-exploitation) auto-runs
                 with no human token. STRUCTURALLY CONFINED — it only lowers the
                 floor for an ATTESTED owned lab (`owned_lab: true` in the
                 engagement AND an `auth_ref` matching `SELF-*`). On any other
                 engagement it fails safe to `gated`, so a client scope can never
                 auto-fire an exploit even if mislabeled `auto_lab`. See
                 `is_owned_lab`. (The Dispatcher ceiling still applies: to
                 auto-run post-exploit the engagement `ceiling` must be
                 `post_exploit`.)

For gated/auto_low/aggressive, FLOOR always gates — the hard floor the dial can't
lower. auto_lab is the ONLY mode that lowers it, and ONLY on an attested lab.
"""

from __future__ import annotations

import re
from enum import Enum

from ..action import Action, BlastRadius
from .catalog import GateClass, InternalExploit

VALID_MODES = ("gated", "auto_low", "aggressive", "auto_lab")

# An owned-lab attestation requires the engagement to explicitly self-declare
# `owned_lab: true` AND carry a self-authorization reference (`SELF-...`). Both
# are required; the default (missing flag or a client `auth_ref`) is not a lab.
_SELF_AUTH_RE = re.compile(r"^SELF-", re.IGNORECASE)


def is_owned_lab(eng: dict) -> bool:
    """True only for an engagement attested as the operator's own lab.

    Gate for the `auto_lab` mode's floor-lowering. Deliberately strict and
    fail-closed: a client engagement cannot satisfy this by accident because it
    demands an explicit `owned_lab: true` flag alongside a `SELF-*` auth_ref.
    """
    if eng.get("owned_lab") is not True:
        return False
    return bool(_SELF_AUTH_RE.match(str(eng.get("auth_ref", ""))))


class Decision(str, Enum):
    AUTO = "auto"   # run now — dispatcher-checked and evidence-logged, no confirm
    GATE = "gate"   # park for a single human ApprovalGate confirmation


def decide(
    mode: str,
    exploit: InternalExploit,
    action: Action,
    owned_lab: bool = False,
) -> Decision:
    # auto_lab: fully autonomous, floor included — but ONLY against an attested
    # owned lab. Without the attestation it fails safe to `gated`, so lowering
    # the floor is structurally impossible off the operator's own lab. Compute
    # `owned_lab` with is_owned_lab(eng); the default (False) is always safe.
    if mode == "auto_lab":
        if owned_lab:
            return Decision.AUTO  # includes FLOOR / post-exploit — owned lab only
        mode = "gated"            # unattested auto_lab is treated as gated

    # The hard floor: disruptive / irreversible / lockout-risk / post-exploit.
    # (auto_lab already returned above when attested; every other mode gates.)
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
