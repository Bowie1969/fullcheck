"""`fcx` — FullCheck-Internal CLI (on-site / internal-network sibling).

Shares scope.yaml and the engagements/ evidence tree with the external tool, so
one engagement holds both external and internal work under one auth reference
and one chain of custody. Mirrors the external command shapes; the one new verb
is `attack`, which routes an exploit technique through the autonomy engine —
AUTO-running CEILING-class techniques (within ceiling) or parking FLOOR-class
ones for the same human ApprovalGate the external tool uses.
"""

from __future__ import annotations

import getpass
import json
from pathlib import Path
from typing import List, Optional

import typer
import yaml
from rich.console import Console
from rich.table import Table

from . import __version__

app = typer.Typer(add_completion=False, help="FullCheck-Internal (fcx) v0.3 — on-site")
console = Console()

ROOT = Path(__file__).resolve().parents[3]
ENGAGEMENTS = ROOT / "engagements"
SCOPE = ROOT / "scope.yaml"


def _eng_dir(client: str) -> Path:
    return ENGAGEMENTS / client


def _load_scope() -> dict:
    if not SCOPE.exists():
        console.print(f"[red]scope.yaml missing[/] at {SCOPE}. Copy scope.internal.example.yaml.")
        raise typer.Exit(1)
    return yaml.safe_load(SCOPE.read_text())


def _require_auth(client: str, auth_ref: str) -> dict:
    cfg = _load_scope()
    eng = cfg.get("engagements", {}).get(client)
    if not eng:
        console.print(f"[red]{client} not in scope.yaml[/].")
        raise typer.Exit(1)
    expected = str(eng.get("auth_ref", ""))
    if not expected:
        console.print(f"[red]{client} has no auth_ref in scope.yaml[/]")
        raise typer.Exit(1)
    if auth_ref != expected:
        console.print(
            "[red]authorization reference mismatch[/]: "
            f"scope.yaml has {expected!r}; --auth-ref was {auth_ref!r}."
        )
        raise typer.Exit(1)
    return eng


def _parse_params(items: Optional[List[str]]) -> dict:
    """Turn repeated `--param k=v` into a dict (split on the first '=' only)."""
    out: dict = {}
    for item in items or []:
        key, sep, val = item.partition("=")
        if not sep:
            raise typer.BadParameter(f"--param must be k=v, got {item!r}")
        out[key.strip()] = val
    return out


@app.command()
def version():
    """Print version."""
    console.print(f"FullCheck-Internal v{__version__}")


@app.command()
def new(client: str, auth_ref: str = typer.Option("", "--auth-ref")):
    """Create an engagement folder skeleton (shared with the external tool)."""
    d = _eng_dir(client)
    (d / "raw").mkdir(parents=True, exist_ok=True)
    (d / "evidence").mkdir(parents=True, exist_ok=True)
    auth = d / "auth.txt"
    if not auth.exists():
        auth.write_text(
            f"Authorization reference: {auth_ref or 'FILL-ME'}\n"
            f"Signed authorization letter MUST be filed before running.\n"
            f"Internal engagement: confirm physical/network access is authorized.\n"
        )
    console.print(f"[green]created[/] {d}")
    console.print("Next: add this engagement to scope.yaml with scope CIDRs, "
                  "ceiling, autonomy and (optional) zone_ceilings, then `fcx swarm`.")


@app.command()
def catalog():
    """List known exploit techniques and their structural gate class."""
    from . import catalog as cat
    from .tools import exploit as _  # noqa: F401 — import populates the catalog

    t = Table(title="Internal exploit catalog")
    t.add_column("technique"); t.add_column("tier"); t.add_column("gate")
    t.add_column("auto in aggressive?")
    for name in sorted(cat.CATALOG):
        cls = cat.CATALOG[name]
        floor = cls.gate_class is cat.GateClass.FLOOR
        t.add_row(
            name,
            cls.blast_radius.value,
            f"[red]FLOOR[/]" if floor else "[green]CEILING[/]",
            "[red]no — always confirm[/]" if floor else "[green]yes[/]",
        )
    console.print(t)
    console.print(
        "\nFLOOR techniques always stop for a human `fcx approve`, even in "
        "aggressive mode. CEILING techniques auto-run within the engagement/zone "
        "ceiling."
    )


@app.command()
def swarm(
    client: str,
    auth_ref: str = typer.Option(..., "--auth-ref"),
    range_: Optional[List[str]] = typer.Option(
        None, "--range", "-r", help="in-scope host or CIDR (repeatable)"
    ),
    targets_file: Optional[Path] = typer.Option(
        None, "--targets", help="file with one host/CIDR per line"
    ),
    workers: int = typer.Option(10, "--workers", help="max concurrent workers (<=50)"),
):
    """Parallel discovery/enumeration fan-out (dispatcher-gated, PROBE/SCAN only).

    Exploitation never runs here — use `fcx attack`. Every task passes the shared
    Dispatcher (scope + engagement/zone ceiling + per-host rate) and writes the
    shared evidence chain.
    """
    from ..orchestrator import run_swarm
    from .pipeline import INTERNAL_DISCOVERY_PIPELINE

    _require_auth(client, auth_ref)
    targets: list[str] = list(range_ or [])
    if targets_file:
        if not targets_file.exists():
            console.print(f"[red]targets file not found[/]: {targets_file}")
            raise typer.Exit(1)
        targets += [
            ln.strip()
            for ln in targets_file.read_text().splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
    targets = list(dict.fromkeys(targets))
    if not targets:
        console.print("[red]no targets[/]; pass --range or --targets.")
        raise typer.Exit(1)

    d = _eng_dir(client)
    d.mkdir(parents=True, exist_ok=True)
    console.print(
        f"[bold]Internal swarm[/] for {client}: {len(targets)} target(s) "
        f"(workers clamped to scope.yaml max_workers and per-host rate)"
    )
    summary = run_swarm(
        engagement=client,
        targets=targets,
        engagement_dir=d,
        auth_ref=auth_ref,
        scope_path=SCOPE,
        workers=workers,
        pipeline=INTERNAL_DISCOVERY_PIPELINE,
        log=lambda m: console.print(m),
    )
    (d / "internal_swarm_summary.json").write_text(json.dumps(summary, indent=2))
    console.print(
        f"[green]done[/] ran={len(summary['ran'])} "
        f"skipped={len(summary['skipped'])} errors={len(summary['errors'])}"
    )


@app.command()
def attack(
    client: str,
    technique: str = typer.Option(..., "--technique", "-t", help="catalog technique name"),
    target: str = typer.Option(..., "--target", help="in-scope host/URL"),
    auth_ref: str = typer.Option(..., "--auth-ref"),
    reason: str = typer.Option("", "--reason", help="why this is justified"),
    param: Optional[List[str]] = typer.Option(
        None, "--param", "-p", help="technique parameter k=v (repeatable)"
    ),
):
    """Route an exploit technique through the autonomy engine.

    CEILING-class + within ceiling + autonomy allows ⇒ runs now (evidence-logged).
    FLOOR-class (or a mode that gates it) ⇒ parked for `fcx approve`. Scope and
    engagement/zone ceiling are always enforced by the Dispatcher either way.
    """
    from ..approval import ApprovalError, ApprovalGate
    from ..dispatcher import CeilingExceeded, Dispatcher, RateLimited, ScopeViolation
    from ..evidence import Evidence
    from .autonomy import Decision, decide
    from .catalog import GateClass, get
    from .tools import exploit as _  # noqa: F401 — import populates the catalog

    eng = _require_auth(client, auth_ref)
    mode = str(eng.get("autonomy", "gated"))
    params = _parse_params(param)
    params["_reason"] = reason

    try:
        exploit = get(technique)
    except KeyError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)

    d = _eng_dir(client)
    d.mkdir(parents=True, exist_ok=True)
    dispatcher = Dispatcher(SCOPE)
    gate = ApprovalGate(d)
    action = exploit._action(target, client, params)  # noqa: SLF001 — inside package
    decision = decide(mode, exploit, action)

    cls_tag = "FLOOR" if exploit.gate_class is GateClass.FLOOR else "CEILING"

    if decision is Decision.GATE:
        try:
            pending = exploit.propose(
                target=target, engagement=client, dispatcher=dispatcher, gate=gate,
                exploit_id=technique, proposed_by=getpass.getuser(), params=params,
            )
        except (ScopeViolation, CeilingExceeded, RateLimited) as e:
            console.print(f"[red]rejected by dispatcher[/]: {e}")
            raise typer.Exit(1)
        except (ApprovalError, ValueError) as e:
            console.print(f"[red]cannot propose[/]: {e}")
            raise typer.Exit(1)
        console.print(
            f"[yellow]{cls_tag} — parked for approval[/] (autonomy={mode}) "
            f"token=[bold]{pending.token}[/]"
        )
        console.print(f"  {technique} -> {target}")
        console.print(f"  [yellow]COMMAND[/]: {' '.join(pending.command)}")
        console.print(f"Next: [bold]fcx approve {client} --auth-ref {auth_ref}[/]")
        return

    # AUTO
    evidence = Evidence(d, auth_ref)
    try:
        res = exploit.run_auto(
            target=target, engagement=client, dispatcher=dispatcher,
            evidence=evidence, params=params,
        )
    except (ScopeViolation, CeilingExceeded, RateLimited) as e:
        console.print(f"[red]rejected by dispatcher[/]: {e}")
        raise typer.Exit(1)
    except (ApprovalError, ValueError) as e:
        console.print(f"[red]cannot auto-run[/]: {e}")
        raise typer.Exit(1)
    console.print(
        f"[green]AUTO-RAN[/] ({cls_tag}, autonomy={mode}) {technique} -> {target} "
        f"(exit {res.exit_code}) evidence={Path(res.artifact_path).name}"
    )


@app.command()
def queue(client: str):
    """List exploits awaiting human approval for this engagement."""
    import time as _t

    from ..approval import ApprovalGate

    gate = ApprovalGate(_eng_dir(client))
    pend = gate.pending()
    if not pend:
        console.print("[green]no pending exploits[/]")
        return
    t = Table(title=f"Pending exploits — {client}")
    t.add_column("token", overflow="fold"); t.add_column("id"); t.add_column("target")
    t.add_column("expires_in(s)"); t.add_column("command", overflow="fold")
    for p in pend:
        t.add_row(p.token, p.exploit_id, p.target,
                  str(round(p.expires_at - _t.time(), 0)), " ".join(p.command))
    console.print(t)


@app.command()
def approve(
    client: str,
    auth_ref: str = typer.Option(..., "--auth-ref"),
    operator: str = typer.Option("", "--operator", help="human confirming (audit)"),
):
    """Walk each pending exploit and record a per-exploit human decision."""
    from ..approval import ApprovalError, ApprovalGate

    _require_auth(client, auth_ref)
    operator = operator or getpass.getuser()
    gate = ApprovalGate(_eng_dir(client))
    pend = gate.pending()
    if not pend:
        console.print("[green]no pending exploits to review[/]")
        return
    console.print(f"[bold]{len(pend)} exploit(s)[/] pending — operator [bold]{operator}[/]\n")
    confirmed = 0
    for p in pend:
        console.print(f"[bold]{p.exploit_id}[/]  ->  [bold]{p.target}[/]")
        console.print(f"  reason: {p.reason or '(none given)'}")
        console.print(f"  proposed_by: {p.proposed_by}")
        console.print(f"  [yellow]COMMAND[/]: {' '.join(p.command)}")
        ans = typer.prompt("  confirm this exploit? [y/N/q]", default="n").strip().lower()
        if ans == "q":
            console.print("  [dim]stopping review[/]")
            break
        confirm = ans in ("y", "yes")
        try:
            rec = gate.decide(p.token, confirm=confirm, decided_by=operator)
        except ApprovalError as e:
            console.print(f"  [red]{e}[/]\n")
            continue
        if confirm:
            confirmed += 1
            console.print(f"  [green]CONFIRMED[/] token={rec.token}\n")
        else:
            console.print("  [red]DENIED[/]\n")
    console.print(f"[bold]{confirmed} confirmed[/].")
    if confirmed:
        console.print(f"Run them: [bold]fcx run {client} --auth-ref {auth_ref}[/]")


@app.command()
def run(
    client: str,
    auth_ref: str = typer.Option(..., "--auth-ref"),
    token: Optional[str] = typer.Option(None, "--token", help="run one; omit for all confirmed"),
):
    """Execute human-confirmed exploits. Each token is single-use (evidence-logged)."""
    from ..approval import ApprovalGate, ExploitStatus
    from ..dispatcher import CeilingExceeded, Dispatcher, RateLimited, ScopeViolation
    from ..evidence import Evidence
    from ..tools.exploit import CommandExploit

    _require_auth(client, auth_ref)
    d = _eng_dir(client)
    gate = ApprovalGate(d)
    all_recs = gate._read()  # noqa: SLF001 — CLI is inside the package
    tokens = [token] if token else [
        tk for tk, r in all_recs.items()
        if r.get("status") == ExploitStatus.CONFIRMED.value
    ]
    if not tokens:
        console.print("[yellow]no confirmed exploits to run[/] (approve some first).")
        raise typer.Exit(0)

    dispatcher = Dispatcher(SCOPE)
    evidence = Evidence(d, auth_ref)
    tool = CommandExploit()  # executes the stored argv for any confirmed token
    ran = 0
    for tk in tokens:
        try:
            res = tool.execute(token=tk, engagement=client, dispatcher=dispatcher,
                               gate=gate, evidence=evidence)
        except Exception as e:  # noqa: BLE001
            console.print(f"[red]skip[/] {tk[:12]}…: {e}")
            continue
        ran += 1
        console.print(
            f"[green]ran[/] {res.exploit_id} -> {res.action.target} "
            f"(exit {res.exit_code}) evidence={Path(res.artifact_path).name}"
        )
    console.print(f"[bold]{ran} exploit(s) executed[/].")


@app.command()
def report(client: str):
    """Render the evidence manifest into a simple internal engagement report."""
    d = _eng_dir(client)
    manifest = d / "evidence" / "manifest.json"
    if not manifest.exists():
        console.print("[red]no evidence[/]; run `fcx swarm` / `fcx attack` first.")
        raise typer.Exit(1)
    m = json.loads(manifest.read_text())
    entries = m.get("entries", [])
    by_tier: dict[str, int] = {}
    for e in entries:
        by_tier[e.get("blast_radius", "?")] = by_tier.get(e.get("blast_radius", "?"), 0) + 1
    lines = [
        f"# Internal engagement report — {client}",
        "",
        f"- Authorization: `{m.get('auth_ref', 'UNKNOWN')}`",
        f"- Evidence artifacts: {len(entries)}",
        f"- By tier: " + ", ".join(f"{k}={v}" for k, v in sorted(by_tier.items())),
        "",
        "## Activity log",
        "",
        "| ts | tool | target | tier | exit |",
        "|----|------|--------|------|------|",
    ]
    for e in entries:
        lines.append(
            f"| {e.get('ts', '')} | {e.get('tool', '')} | {e.get('target', '')} "
            f"| {e.get('blast_radius', '')} | {e.get('exit_code', '')} |"
        )
    out = d / "internal_report.md"
    out.write_text("\n".join(lines) + "\n")
    console.print(f"[green]report[/] -> {out}")


if __name__ == "__main__":
    app()
