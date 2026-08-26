"""`auto_lab` autonomous chain: recon -> LLM plan -> execute -> replan.

This is the "runs the whole recon-to-post-exploit chain itself" driver. It ties
together pieces that already exist and are individually safety-checked; it adds
NO new authority of its own:

  * recon/enum fan-out          -> orchestrator.run_swarm (dispatcher-gated)
  * "choose the next exploits"  -> planner.plan_next_steps (catalog-bound LLM)
  * "should this auto-run?"     -> autonomy.decide (unchanged)
  * run without a human token   -> InternalExploit.run_auto (re-checks FLOOR +
                                   owned_lab, dispatcher-checks, evidence-logs)
  * park for a human instead    -> InternalExploit.propose -> ApprovalGate

The only mode in which a FLOOR / post-exploit step auto-fires is `auto_lab` on an
ATTESTED owned lab (`autonomy.is_owned_lab`). On every other engagement the
identical loop runs, but each FLOOR step is PARKED for `fcx approve` — the chain
self-drives discovery and reversible reads, and stops for a human on anything
disruptive. That degradation is structural (autonomy.decide), not a flag here.

Bounds that keep it from running away:
  * `max_rounds`  — how many plan/execute cycles (LLM calls) at most.
  * `max_steps`   — steps per round the planner may return.
  * dedupe        — a (technique, target, params) is never run/proposed twice.
  * the LLM returning [] ends the chain early ("nothing useful left").
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from ..approval import ApprovalError, ApprovalGate
from ..dispatcher import CeilingExceeded, Dispatcher, RateLimited, ScopeViolation
from ..evidence import Evidence
from ..llm.client import LlmError, OpenClawClient
from ..orchestrator import run_swarm
from . import catalog as cat
from .autonomy import Decision, decide, is_owned_lab
from .pipeline import INTERNAL_DISCOVERY_PIPELINE
from .planner import PlannedStep, plan_next_steps
from .tools import exploit as _exploit  # noqa: F401 — import populates the catalog


def summarize_state(raw_dir: Path, max_chars: int = 24000, per_artifact: int = 2500) -> str:
    """Collate the evidence `raw/` artifacts into one bounded planning payload.

    Reads newest-first so the latest recon and the latest exploit output (both
    land here as JSON blobs) are what the planner sees. This is how a recovered
    credential from one round becomes available to the next round's plan.
    """
    if not raw_dir.exists():
        return "(no evidence yet)"
    arts = sorted(raw_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    chunks: list[str] = []
    total = 0
    for art in arts:
        try:
            blob = json.loads(art.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        act = blob.get("action", {})
        stdout = (blob.get("stdout") or "").strip()
        if not stdout:
            continue
        chunk = (
            f"### {act.get('tool')} -> {act.get('target')} "
            f"[{act.get('blast_radius')}] exit={blob.get('exit_code')}\n"
            f"{stdout[:per_artifact]}\n"
        )
        if total + len(chunk) > max_chars:
            break
        chunks.append(chunk)
        total += len(chunk)
    return "\n".join(chunks) or "(no evidence yet)"


def _step_key(step: PlannedStep) -> str:
    return f"{step.technique}|{step.target}|{json.dumps(step.params, sort_keys=True)}"


def run_autochain(
    *,
    client: str,
    auth_ref: str,
    eng: dict,
    scope_path: Path,
    engagement_dir: Path,
    targets: list[str],
    workers: int = 10,
    max_rounds: int = 4,
    max_steps: int = 8,
    skip_recon: bool = False,
    llm: OpenClawClient | None = None,
    log: Callable[[str], None] = print,
) -> dict[str, Any]:
    """Drive the full autonomous chain for one engagement. Returns a summary dict.

    `eng` is the engagement block from scope.yaml (already auth-verified by the
    caller). Whether FLOOR auto-runs is decided solely by mode + is_owned_lab(eng);
    this function never lowers a gate itself.
    """
    mode = str(eng.get("autonomy", "gated"))
    owned_lab = is_owned_lab(eng)
    ceiling = str(eng.get("ceiling", "probe"))
    scope = [str(x) for x in (eng.get("scope") or [])]
    out_of_scope = [str(x) for x in (eng.get("out_of_scope") or [])]
    interface = eng.get("interface")

    result: dict[str, Any] = {
        "mode": mode,
        "owned_lab": owned_lab,
        "rounds": 0,
        "ran": [],       # auto-executed (evidence-logged)
        "parked": [],     # FLOOR steps parked for human approval (tokens)
        "rejected": [],   # dispatcher said no (scope/ceiling/zone/rate)
        "errors": [],     # bad params / build errors
    }

    # ---- phase 1: recon fan-out (unless caller already has evidence) ---------
    if not skip_recon and targets:
        log("[bold]phase 1 — recon/enum swarm[/]")
        run_swarm(
            engagement=client,
            targets=targets,
            engagement_dir=engagement_dir,
            auth_ref=auth_ref,
            scope_path=scope_path,
            workers=workers,
            pipeline=INTERNAL_DISCOVERY_PIPELINE,
            log=log,
        )

    dispatcher = Dispatcher(scope_path)
    evidence = Evidence(engagement_dir, auth_ref)
    gate = ApprovalGate(engagement_dir)
    llm = llm or OpenClawClient()
    seen: set[str] = set()
    already_desc: list[str] = []

    # ---- phase 2: plan -> execute -> replan loop -----------------------------
    for rnd in range(1, max_rounds + 1):
        result["rounds"] = rnd
        state = summarize_state(evidence.raw)
        log(f"[bold]phase 2 — planning round {rnd}/{max_rounds}[/]")
        try:
            steps = plan_next_steps(
                state=state,
                scope=scope,
                out_of_scope=out_of_scope,
                ceiling=ceiling,
                already_run=already_desc,
                max_steps=max_steps,
                client=llm,
            )
        except LlmError as e:
            log(f"[red]planner/LLM error — aborting chain[/]: {e}")
            result["errors"].append({"round": rnd, "error": f"llm: {e}"})
            break

        if not steps:
            log("[green]planner returned no further steps — chain complete[/]")
            break

        ran_this_round = 0
        for step in steps:
            key = _step_key(step)
            if key in seen:
                continue
            seen.add(key)
            already_desc.append(f"{step.technique} -> {step.target}")

            try:
                exploit = cat.get(step.technique)  # catalog-bound (validated again)
            except KeyError as e:
                result["errors"].append({"technique": step.technique, "error": str(e)})
                continue

            params = dict(step.params)
            # Convenience: supply the engagement NIC to MITM techniques that need
            # it, so the planner needn't guess the drop box's interface name.
            if interface and "interface" not in params and "interface" in exploit.param_hint:
                params["interface"] = interface
            params["_reason"] = step.reason

            action = exploit._action(step.target, client, params)  # noqa: SLF001
            decision = decide(mode, exploit, action, owned_lab=owned_lab)
            is_floor = exploit.gate_class is cat.GateClass.FLOOR

            if decision is Decision.GATE:
                try:
                    pending = exploit.propose(
                        target=step.target, engagement=client, dispatcher=dispatcher,
                        gate=gate, exploit_id=step.technique, proposed_by="auto-planner",
                        params=params,
                    )
                except (ScopeViolation, CeilingExceeded, RateLimited) as e:
                    log(f"  [yellow]rejected[/] {step.technique} -> {step.target}: {e}")
                    result["rejected"].append(
                        {"technique": step.technique, "target": step.target, "why": str(e)}
                    )
                    continue
                except (ApprovalError, ValueError) as e:
                    log(f"  [red]cannot propose[/] {step.technique}: {e}")
                    result["errors"].append(
                        {"technique": step.technique, "target": step.target, "error": str(e)}
                    )
                    continue
                log(
                    f"  [yellow]PARKED for approval[/] {step.technique} -> {step.target} "
                    f"token={pending.token}"
                )
                result["parked"].append(
                    {"technique": step.technique, "target": step.target, "token": pending.token}
                )
                continue

            # AUTO — reachable for FLOOR only via attested auto_lab (owned lab).
            if is_floor:
                log(
                    f"  [bold red]⚠ auto_lab AUTO-FIRING FLOOR[/] {step.technique} -> "
                    f"{step.target} (attested owned lab; no human confirm; evidence-logged)"
                )
            try:
                res = exploit.run_auto(
                    target=step.target, engagement=client, dispatcher=dispatcher,
                    evidence=evidence, params=params, owned_lab=owned_lab,
                )
            except (ScopeViolation, CeilingExceeded, RateLimited) as e:
                log(f"  [yellow]rejected[/] {step.technique} -> {step.target}: {e}")
                result["rejected"].append(
                    {"technique": step.technique, "target": step.target, "why": str(e)}
                )
                continue
            except (ApprovalError, ValueError) as e:
                log(f"  [red]cannot auto-run[/] {step.technique}: {e}")
                result["errors"].append(
                    {"technique": step.technique, "target": step.target, "error": str(e)}
                )
                continue
            ran_this_round += 1
            log(
                f"  [green]AUTO-RAN[/] {step.technique} -> {step.target} "
                f"(exit {res.exit_code}) evidence={Path(res.artifact_path).name}"
            )
            result["ran"].append(
                {
                    "technique": step.technique,
                    "target": step.target,
                    "exit_code": res.exit_code,
                    "evidence": Path(res.artifact_path).name,
                }
            )

        # If a round produced no new auto-executed evidence, replanning on the
        # same state will just loop — stop. (Parked steps await a human anyway.)
        if ran_this_round == 0:
            log("[green]no new auto-executed steps this round — chain complete[/]")
            break

    return result
