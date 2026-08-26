"""M365 active-technique catalog — every entry is FLOOR-gated.

Anything that sends a credential or an auth attempt at a live tenant (password
spray, MFA-fatigue push-bombing, illicit OAuth consent, token replay) carries
real lockout, alerting, and user-impact risk. None of it may ever run on an auto
path. So — exactly like the internal catalog's FLOOR class — these techniques
route through the SAME human ApprovalGate the rest of FullCheck uses:

  1. the engagement `ceiling` in scope.yaml must be `exploit` (Dispatcher, gate 1);
  2. a human confirms the exact command and a single-use token is burned on run
     (ApprovalGate, gate 2).

Reuse, not reinvention: each technique subclasses the external `Exploit` base, so
`propose()`/`execute()` and the whole `fullcheck m365 attack -> approve -> run`
flow is the existing, tested exploit path — the tenant domain is just the target,
and the Dispatcher enforces `ceiling: exploit` on it. `build_cmd` returns the
exact argv the human will see; several techniques are intentionally left as
`stub=True` (they raise on build) until a real, authorized tool invocation is
wired — shipping the gate without shipping a live sprayer.

Adding a technique (agents, read this): subclass `M365Technique`, set `name`,
`blast_radius` (EXPLOIT or POST_EXPLOIT), a one-line risk note in the docstring,
and either a real `build_cmd` OR `stub = True`. Decorate with `@register`. Do NOT
set a CEILING/auto path — M365 active work is FLOOR-only by policy.
"""

from __future__ import annotations

from enum import Enum
from typing import Sequence

from ..action import BlastRadius
from ..tools.exploit import Exploit


class GateClass(str, Enum):
    FLOOR = "floor"  # M365 active techniques are FLOOR-only, always human-gated


class M365Technique(Exploit):
    """A FLOOR-gated active M365 technique. Target is the tenant domain."""

    gate_class: GateClass = GateClass.FLOOR
    stub: bool = False           # True => not yet wired to a live tool; build raises
    risk: str = ""               # short human note shown at approval time

    def build_cmd(self, target: str, params: dict) -> Sequence[str]:
        if self.stub:
            raise NotImplementedError(
                f"{self.name} is a gated stub in v0.2 — no live invocation is wired "
                f"yet. Implement build_cmd against an authorized tool before use."
            )
        return self._build(target, params)

    def _build(self, target: str, params: dict) -> Sequence[str]:
        raise NotImplementedError


CATALOG: dict[str, type[M365Technique]] = {}


def register(cls: type[M365Technique]) -> type[M365Technique]:
    if not cls.name:
        raise ValueError(f"{cls.__name__} must set a non-empty name to register")
    if cls.name in CATALOG:
        raise ValueError(f"duplicate technique name: {cls.name}")
    CATALOG[cls.name] = cls
    return cls


def get(name: str) -> M365Technique:
    if name not in CATALOG:
        known = ", ".join(sorted(CATALOG)) or "(none loaded)"
        raise KeyError(f"unknown technique {name!r}; known: {known}")
    return CATALOG[name]()


def load_techniques() -> dict[str, type[M365Technique]]:
    from . import techniques as _  # noqa: F401 — import populates CATALOG

    return CATALOG
