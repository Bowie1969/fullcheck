"""`fullcheck m365 ...` — the Microsoft 365 / Entra ID subcommand group.

Wired into the top-level app as a Typer sub-app. Verbs:
  recon    — unauthenticated tenant recon (PASSIVE) + optional user-enum (PROBE)
  scan     — authenticated Graph reads (SCAN, needs an app registration)
  analyze  — deterministic findings from the recon/scan artifacts
  report   — render findings into m365_report.md
  catalog  — list the FLOOR-gated active techniques
  attack   — park a FLOOR-gated technique for the existing human ApprovalGate

Scope/auth is enforced by the shared spine: the target is the client tenant
domain, which must be in scope.yaml, and the engagement ceiling gates the tier
(scan needs `scan`, attack needs `exploit`). Nothing here bypasses that.
"""

from __future__ import annotations

import getpass
import json
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

console = Console()

# Resolved lazily so this module imports without the parent CLI's globals.
ROOT = Path(__file__).resolve().parents[3]
ENGAGEMENTS = ROOT / "engagements"
SCOPE = ROOT / "scope.yaml"

app = typer.Typer(add_completion=False, help="Microsoft 365 / Entra ID assessment (v0.2)")


def _eng_dir(client: str) -> Path:
    return ENGAGEMENTS / client


def _require_auth(client: str, auth_ref: str) -> dict:
    import yaml

    if not SCOPE.exists():
        console.print(f"[red]scope.yaml missing[/] at {SCOPE}.")
        raise typer.Exit(1)
    cfg = yaml.safe_load(SCOPE.read_text())
    eng = cfg.get("engagements", {}).get(client)
    if not eng:
        console.print(f"[red]{client} not in scope.yaml[/].")
        raise typer.Exit(1)
    expected = str(eng.get("auth_ref", ""))
    if not expected or auth_ref != expected:
        console.print(
            "[red]authorization reference mismatch[/]: "
            f"scope.yaml has {expected!r}; --auth-ref was {auth_ref!r}."
        )
        raise typer.Exit(1)
    return eng


@app.command()
def catalog():
    """List the FLOOR-gated active M365 techniques (all human-confirmed)."""
    from .catalog import CATALOG, load_techniques

    load_techniques()
    t = Table(title="M365 active-technique catalog (all FLOOR — human-gated)")
    t.add_column("technique"); t.add_column("tier"); t.add_column("state"); t.add_column("risk")
    for name in sorted(CATALOG):
        cls = CATALOG[name]
        state = "[yellow]stub[/]" if cls.stub else "[green]wired[/]"
        t.add_row(name, cls.blast_radius.value, state, cls.risk or "")
    console.print(t)
    console.print(
        "\nEvery technique requires [bold]ceiling: exploit[/] in scope.yaml AND a "
        "per-action human confirm token. None auto-run. `stub` techniques raise "
        "on propose until a live invocation is deliberately wired."
    )


@app.command()
def recon(
    client: str,
    domain: str = typer.Option(..., "--domain", "-d", help="client tenant domain (must be in scope)"),
    auth_ref: str = typer.Option(..., "--auth-ref"),
    users: Optional[Path] = typer.Option(
        None, "--users", help="candidate accounts for PROBE-tier enumeration (one/line)"
    ),
):
    """Unauthenticated tenant recon (PASSIVE) + optional user-enum (PROBE)."""
    from ..dispatcher import Dispatcher
    from ..evidence import Evidence
    from .base import run_recon

    eng = _require_auth(client, auth_ref)
    d = _eng_dir(client)
    d.mkdir(parents=True, exist_ok=True)
    params: dict = {}
    if users:
        if not users.exists():
            console.print(f"[red]users file not found[/]: {users}")
            raise typer.Exit(1)
        params["users"] = str(users)
    console.print(f"[bold]M365 recon[/] for {client} on tenant [bold]{domain}[/]")
    summary = run_recon(
        domain=domain,
        engagement=client,
        dispatcher=Dispatcher(SCOPE),
        evidence=Evidence(d, auth_ref),
        params=params,
        log=lambda m: console.print(m),
    )
    (d / "m365_recon_summary.json").write_text(json.dumps(summary, indent=2))
    console.print(
        f"[green]done[/] ran={len(summary['ran'])} "
        f"skipped={len(summary['skipped'])} errors={len(summary['errors'])}"
    )


@app.command()
def scan(
    client: str,
    domain: str = typer.Option(..., "--domain", "-d", help="client tenant domain (must be in scope)"),
    auth_ref: str = typer.Option(..., "--auth-ref"),
):
    """Authenticated Graph reads (SCAN). Needs an app registration (see docs/M365.md)."""
    from ..dispatcher import Dispatcher
    from ..evidence import Evidence
    from .graph import GraphError, load_creds, run_scan

    _require_auth(client, auth_ref)
    d = _eng_dir(client)
    d.mkdir(parents=True, exist_ok=True)
    try:
        creds = load_creds(d)
    except GraphError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)
    flow = "device-code" if creds.use_device_code else "client-credentials"
    console.print(f"[bold]M365 Graph scan[/] for {client} on [bold]{domain}[/] ({flow})")
    try:
        summary = run_scan(
            domain=domain, engagement=client, engagement_dir=d,
            dispatcher=Dispatcher(SCOPE), evidence=Evidence(d, auth_ref),
            creds=creds, log=lambda m: console.print(m),
        )
    except GraphError as e:
        console.print(f"[red]scan failed[/]: {e}")
        raise typer.Exit(1)
    (d / "m365_scan_summary.json").write_text(json.dumps(summary, indent=2))
    console.print(
        f"[green]done[/] ran={len(summary['ran'])} skipped={len(summary['skipped'])}"
    )


@app.command()
def analyze(
    client: str,
    domain: str = typer.Option(..., "--domain", "-d", help="tenant domain analyzed"),
):
    """Deterministic findings from the recon/scan artifacts -> m365_findings.json."""
    from .analyze import analyze as run_analyze

    d = _eng_dir(client)
    raw = d / "raw"
    if not raw.exists():
        console.print("[red]no artifacts[/]; run `fullcheck m365 recon`/`scan` first.")
        raise typer.Exit(1)
    findings = run_analyze(raw, domain, log=lambda m: console.print(m))
    (d / "m365_findings.json").write_text(json.dumps(findings, indent=2))
    console.print(f"[green]{len(findings)} finding(s)[/] -> {d/'m365_findings.json'}")


@app.command()
def report(
    client: str,
    domain: str = typer.Option(..., "--domain", "-d", help="tenant domain"),
    auth_ref: str = typer.Option("", "--auth-ref"),
):
    """Render m365_findings.json into m365_report.md."""
    from ..report.generator import generate

    d = _eng_dir(client)
    fj = d / "m365_findings.json"
    findings = json.loads(fj.read_text()) if fj.exists() else []
    eng = {}
    try:
        eng = _require_auth(client, auth_ref) if auth_ref else {}
    except typer.Exit:
        eng = {}
    out = generate(
        engagement_dir=d, client=client, engagement=client,
        auth_ref=eng.get("auth_ref", auth_ref or "UNKNOWN"),
        scope=[domain], findings=findings, out_name="m365_report.md",
    )
    console.print(f"[green]report[/] -> {out}")


@app.command()
def attack(
    client: str,
    technique: str = typer.Option(..., "--technique", "-t", help="catalog technique name"),
    domain: str = typer.Option(..., "--domain", "-d", help="client tenant domain (must be in scope)"),
    auth_ref: str = typer.Option(..., "--auth-ref"),
    reason: str = typer.Option("", "--reason", help="why this is justified"),
    param: Optional[List[str]] = typer.Option(
        None, "--param", "-p", help="technique parameter k=v (repeatable)"
    ),
):
    """Park a FLOOR-gated technique for human approval. NEVER auto-runs.

    Validates scope + `ceiling: exploit` via the Dispatcher, then queues the exact
    command for `fullcheck approve` + `fullcheck exploit-run` (the shared HITL
    exploit path). A `stub` technique refuses here — nothing is wired to fire.
    """
    from ..approval import ApprovalError, ApprovalGate
    from ..dispatcher import CeilingExceeded, Dispatcher, RateLimited, ScopeViolation
    from .catalog import get, load_techniques

    _require_auth(client, auth_ref)
    load_techniques()
    try:
        tech = get(technique)
    except KeyError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)

    d = _eng_dir(client)
    d.mkdir(parents=True, exist_ok=True)
    params = {}
    for item in param or []:
        k, sep, v = item.partition("=")
        if not sep:
            console.print(f"[red]--param must be k=v[/]: {item!r}")
            raise typer.Exit(1)
        params[k.strip()] = v
    params["_reason"] = reason

    try:
        pending = tech.propose(
            target=domain, engagement=client, dispatcher=Dispatcher(SCOPE),
            gate=ApprovalGate(d), exploit_id=technique, proposed_by=getpass.getuser(),
            params=params,
        )
    except (ScopeViolation, CeilingExceeded, RateLimited) as e:
        console.print(f"[red]rejected by dispatcher[/]: {e}")
        raise typer.Exit(1)
    except NotImplementedError as e:
        console.print(f"[yellow]technique is a gated stub[/]: {e}")
        raise typer.Exit(1)
    except (ApprovalError, ValueError) as e:
        console.print(f"[red]cannot propose[/]: {e}")
        raise typer.Exit(1)
    console.print(f"[yellow]FLOOR — parked for approval[/] token=[bold]{pending.token}[/]")
    console.print(f"  {technique} -> {domain}")
    console.print(f"  [yellow]COMMAND[/]: {' '.join(pending.command)}")
    console.print(
        f"Next: [bold]fullcheck approve {client} --auth-ref {auth_ref}[/] then "
        f"[bold]fullcheck exploit-run {client} --auth-ref {auth_ref}[/]"
    )


if __name__ == "__main__":
    app()
