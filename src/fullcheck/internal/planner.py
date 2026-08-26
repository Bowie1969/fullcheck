"""LLM exploit planner — the "choose its own exploits" brain for `auto_lab`.

Given the current recon/evidence STATE, the LLM proposes the next batch of
techniques to run. It is a *proposer only*: it names a technique + target +
params, and nothing else. Three properties keep that safe and are enforced HERE,
not trusted to the model:

  1. **Catalog-bound.** A proposed step is dropped unless its `technique` is a
     real key in `catalog.CATALOG`. The LLM can never introduce a technique or a
     raw command — `build_cmd` stays deterministic and lives in the catalog.
  2. **Impact is not the LLM's to set.** The model does not (and cannot) choose
     blast radius or gate class; those come from the catalog class. This module
     ignores any such fields if the model emits them.
  3. **Enforcement is downstream.** Scope, ceiling, zone, rate (Dispatcher) and
     the FLOOR/owned-lab decision (autonomy.decide + run_auto) all still run on
     every step. The planner only decides what is *useful*, never what is *allowed*.

So the worst a misbehaving or prompt-injected model can do is waste a round: pick
an out-of-scope or over-ceiling technique that the Dispatcher then rejects, or a
FLOOR technique that (off an attested lab) simply parks for human approval.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..llm.client import LlmError, OpenClawClient
from .catalog import CATALOG

_PROMPT = (Path(__file__).parent / "plan_prompt.txt").read_text()


@dataclass
class PlannedStep:
    technique: str
    target: str
    params: dict = field(default_factory=dict)
    reason: str = ""


def technique_menu() -> list[dict[str, Any]]:
    """The menu the LLM may choose from — built from the live catalog.

    Importing the technique module (done by the caller / autochain) is what
    populates CATALOG; this reflects whatever is registered.
    """
    out: list[dict[str, Any]] = []
    for name in sorted(CATALOG):
        cls = CATALOG[name]
        doc = (cls.__doc__ or "").strip().splitlines()
        out.append(
            {
                "technique": name,
                "tier": cls.blast_radius.value,
                "impact_class": cls.gate_class.value,  # informational only
                "params": cls.param_hint or "(see description)",
                "description": doc[0].strip() if doc else "",
            }
        )
    return out


def _build_user_payload(
    state: str,
    scope: list[str],
    out_of_scope: list[str],
    ceiling: str,
    already_run: list[str],
    max_steps: int,
) -> str:
    menu = json.dumps(technique_menu(), indent=2)
    scope_block = ", ".join(scope) or "(none)"
    oos_block = ", ".join(out_of_scope) or "(none)"
    run_block = "\n".join(f"- {r}" for r in already_run) or "(nothing run yet)"
    return (
        f"## TECHNIQUE MENU (choose by exact `technique` name only)\n{menu}\n\n"
        f"## SCOPE (in-scope targets)\n{scope_block}\n\n"
        f"## OUT OF SCOPE (never target)\n{oos_block}\n\n"
        f"## ENGAGEMENT CEILING\n{ceiling}\n\n"
        f"## ALREADY RUN (do not repeat)\n{run_block}\n\n"
        f"## CURRENT STATE (recon + prior step output, most recent first)\n{state}\n\n"
        f"## INSTRUCTION\nPropose at most {max_steps} next step(s) as a JSON array, "
        f"most-useful-first. Return [] if nothing evidence-grounded remains."
    )


def _coerce_steps(raw: Any) -> list[dict]:
    """Accept either a bare array or a {\"steps\": [...]} wrapper; else []."""
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    if isinstance(raw, dict):
        for key in ("steps", "plan", "actions"):
            val = raw.get(key)
            if isinstance(val, list):
                return [x for x in val if isinstance(x, dict)]
    return []


def validate_steps(raw_steps: list[dict], max_steps: int) -> list[PlannedStep]:
    """Turn raw LLM dicts into PlannedSteps, dropping anything not catalog-valid.

    This is the trust boundary for planner output: an unknown technique, a
    missing/blank target, or a non-dict params is silently discarded rather than
    trusted. A dropped step can never reach the Dispatcher or the ApprovalGate.
    """
    steps: list[PlannedStep] = []
    for item in raw_steps:
        technique = str(item.get("technique", "")).strip()
        target = str(item.get("target", "")).strip()
        if technique not in CATALOG:  # (1) catalog-bound — no invented techniques
            continue
        if not target:
            continue
        params = item.get("params", {})
        if not isinstance(params, dict):
            params = {}
        # The model does not get to set gating/impact/tier — strip if present.
        params = {
            k: v
            for k, v in params.items()
            if k not in ("blast_radius", "gate_class", "tier", "_reason")
        }
        steps.append(
            PlannedStep(
                technique=technique,
                target=target,
                params=params,
                reason=str(item.get("reason", "")).strip(),
            )
        )
        if len(steps) >= max_steps:
            break
    return steps


def plan_next_steps(
    state: str,
    scope: list[str],
    out_of_scope: list[str],
    ceiling: str,
    already_run: list[str],
    max_steps: int = 8,
    client: OpenClawClient | None = None,
) -> list[PlannedStep]:
    """Ask the LLM for the next validated batch of steps.

    Raises LlmError if the model is unreachable or returns unparseable output —
    the caller must ABORT the chain on that, never fall back to running
    arbitrary techniques.
    """
    client = client or OpenClawClient()
    user = _build_user_payload(
        state, scope, out_of_scope, ceiling, already_run, max_steps
    )
    raw = client.chat_json(_PROMPT, user)
    return validate_steps(_coerce_steps(raw), max_steps)
