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
from .runner import run_recon, correlate_cves
from .intel.cve_cache import CveCache

app = typer.Typer(add_completion=False, help="FullCheck v0.1 external checkup")
console = Console()

from .m365.cli import app as m365_app  # noqa: E402

app.add_typer(m365_app, name="m365")

ROOT = Path(__file__).resolve().parents[2]
ENGAGEMENTS = ROOT / "engagements"
SCOPE = ROOT / "scope.yaml"
CVE_DB = ROOT / "intel" / "cache.db"


def _eng_dir(client: str) -> Path:
    return ENGAGEMENTS / client


def _load_scope() -> dict:
    if not SCOPE.exists():
        console.print(f"[red]scope.yaml missing[/]. Copy scope.yaml.example.")
        raise typer.Exit(1)
    return yaml.safe_load(SCOPE.read_text())


def _require_auth(client: str, auth_ref: str) -> dict:
    """Load an engagement and verify the supplied auth_ref matches scope.yaml."""
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


@app.command()
def version():
    """Print version."""
    console.print(f"FullCheck v{__version__}")


@app.command()
def new(client: str, auth_ref: str = typer.Option("", "--auth-ref")):
    """Create an engagement folder skeleton."""
    d = _eng_dir(client)
    (d / "raw").mkdir(parents=True, exist_ok=True)
    (d / "evidence").mkdir(parents=True, exist_ok=True)
    auth = d / "auth.txt"
    if not auth.exists():
        auth.write_text(
            f"Authorization reference: {auth_ref or 'FILL-ME'}\n"
            f"Signed authorization letter MUST be filed before running.\n"
        )
    console.print(f"[green]created[/] {d}")
    console.print("Next: add this engagement to scope.yaml, then `fullcheck run`.")


@app.command()
def run(
    client: str,
    scope: str = typer.Option(..., "--scope", help="root domain to assess"),
    auth_ref: str = typer.Option(..., "--auth-ref"),
):
    """Execute the recon pipeline (dispatcher-gated)."""
    cfg = _load_scope()
    eng = cfg.get("engagements", {}).get(client)
    if not eng:
        console.print(
            f"[red]{client} not in scope.yaml[/]. Add it (with auth_ref, "
            f"ceiling, scope) before running."
        )
        raise typer.Exit(1)
    expected_ref = str(eng.get("auth_ref", ""))
    if not expected_ref:
        console.print(f"[red]{client} has no auth_ref in scope.yaml[/]")
        raise typer.Exit(1)
    if auth_ref != expected_ref:
        console.print(
            "[red]authorization reference mismatch[/]: "
            f"scope.yaml has {expected_ref!r}; --auth-ref was {auth_ref!r}."
        )
        raise typer.Exit(1)
    d = _eng_dir(client)
    d.mkdir(parents=True, exist_ok=True)
    console.print(f"[bold]Running recon[/] for {client} on {scope}")
    summary = run_recon(
        engagement=client,
        targets=[scope],
        engagement_dir=d,
        auth_ref=auth_ref,
        scope_path=SCOPE,
        log=lambda m: console.print(m),
    )
    (d / "run_summary.json").write_text(json.dumps(summary, indent=2))
    console.print(
        f"[green]done[/] ran={len(summary['ran'])} "
        f"skipped={len(summary['skipped'])} errors={len(summary['errors'])}"
    )


@app.command()
def triage(client: str):
    """LLM-triage raw findings into ranked findings.json (via OpenClaw)."""
    from .llm.triage import triage as run_triage

    d = _eng_dir(client)
    raw = d / "raw"
    if not raw.exists() or not any(raw.glob("*.json")):
        console.print("[red]no raw artifacts[/]; run `fullcheck run` first.")
        raise typer.Exit(1)
    console.print("Correlating CVEs...")
    cve_matches = correlate_cves(raw, CVE_DB, log=lambda m: console.print(m))
    console.print("Calling OpenClaw for triage...")
    try:
        findings = run_triage(raw, cve_matches)
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]triage failed[/]: {e}")
        raise typer.Exit(1)
    (d / "findings.json").write_text(json.dumps(findings, indent=2))
    console.print(f"[green]{len(findings)} findings[/] -> {d/'findings.json'}")


@app.command()
def report(client: str):
    """Render findings.json into a markdown report."""
    from .report.generator import generate

    cfg = _load_scope()
    eng = cfg.get("engagements", {}).get(client, {})
    d = _eng_dir(client)
    fj = d / "findings.json"
    findings = json.loads(fj.read_text()) if fj.exists() else []
    out = generate(
        engagement_dir=d,
        client=client,
        engagement=client,
        auth_ref=eng.get("auth_ref", "UNKNOWN"),
        scope=eng.get("scope", []),
        findings=findings,
    )
    console.print(f"[green]report[/] -> {out}")


@app.command(name="update-intel")
def update_intel(
    years: str = typer.Option("2024,2025,2026", help="comma-separated NVD years"),
    embeddings: bool = typer.Option(
        False, "--embeddings/--no-embeddings",
        help="also build the semantic vector index (needs a GPU-ish box)",
    ),
):
    """Build/refresh the local CVE cache from NVD feeds."""
    cache = CveCache(CVE_DB, use_embeddings=False)
    for y in [int(x) for x in years.split(",")]:
        console.print(f"loading NVD {y}...")
        try:
            n = cache.load_year(y, log=lambda m: console.print(f"  {m}"))
            console.print(f"  [green]{n} CVEs[/] for {y}")
        except Exception as e:  # noqa: BLE001
            console.print(f"  [red]failed {y}[/]: {e}")
    if embeddings:
        console.print("building semantic index (this can take a while)...")
        n = cache.build_embeddings(log=lambda m: console.print(f"  {m}"))
        console.print(
            f"  [green]{n} vectors[/]" if n else "  [yellow]skipped[/] (see message above)"
        )


@app.command(name="build-embeddings")
def build_embeddings():
    """Build the semantic vector index over the existing CVE cache."""
    if not CVE_DB.exists():
        console.print("[red]no CVE cache[/]; run `fullcheck update-intel` first.")
        raise typer.Exit(1)
    cache = CveCache(CVE_DB, use_embeddings=False)
    n = cache.build_embeddings(log=lambda m: console.print(f"  {m}"))
    console.print(f"[green]{n} vectors[/]" if n else "[yellow]skipped[/]")


@app.command()
def swarm(
    client: str,
    auth_ref: str = typer.Option(..., "--auth-ref"),
    scope: Optional[str] = typer.Option(
        None, "--scope", help="single root/host to assess"
    ),
    targets_file: Optional[Path] = typer.Option(
        None, "--targets", help="file with one target per line (fans out in parallel)"
    ),
    workers: int = typer.Option(10, "--workers", help="max concurrent workers (<=50)"),
):
    """Parallel recon/scan fan-out across many targets (dispatcher-gated).

    Exploitation never runs here — use `exploit-propose` -> `approve` ->
    `exploit-run`. This only runs passive/probe/scan-tier tools concurrently,
    bounded by --workers and the per-host rate limit in scope.yaml.
    """
    from .orchestrator import run_swarm

    _require_auth(client, auth_ref)
    targets: list[str] = []
    if scope:
        targets.append(scope)
    if targets_file:
        if not targets_file.exists():
            console.print(f"[red]targets file not found[/]: {targets_file}")
            raise typer.Exit(1)
        targets += [
            ln.strip()
            for ln in targets_file.read_text().splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
    targets = list(dict.fromkeys(targets))  # de-dupe, keep order
    if not targets:
        console.print("[red]no targets[/]; pass --scope or --targets file.")
        raise typer.Exit(1)

    d = _eng_dir(client)
    d.mkdir(parents=True, exist_ok=True)
    console.print(
        f"[bold]Swarm recon[/] for {client}: {len(targets)} target(s) "
        f"(worker count clamped to scope.yaml max_workers and the per-host rate limit)"
    )
    summary = run_swarm(
        engagement=client,
        targets=targets,
        engagement_dir=d,
        auth_ref=auth_ref,
        scope_path=SCOPE,
        workers=workers,
        log=lambda m: console.print(m),
    )
    (d / "swarm_summary.json").write_text(json.dumps(summary, indent=2))
    console.print(
        f"[green]done[/] ran={len(summary['ran'])} "
        f"skipped={len(summary['skipped'])} errors={len(summary['errors'])}"
    )


@app.command(name="exploit-propose")
def exploit_propose(
    client: str,
    target: str = typer.Option(..., "--target", help="in-scope host/URL to exploit"),
    exploit_id: str = typer.Option(..., "--id", help="label, e.g. CVE-2023-37474"),
    auth_ref: str = typer.Option(..., "--auth-ref"),
    reason: str = typer.Option("", "--reason", help="why this is justified"),
    command: List[str] = typer.Argument(
        ..., help="the exact argv to run (after --), e.g. curl -sik http://...",
    ),
):
    """Park an exploit for human approval. Validates scope+ceiling; does NOT run.

    The engagement must have `ceiling: exploit` in scope.yaml or this is rejected
    before it ever reaches the queue. What you pass as the command is exactly
    what a human will confirm and what will later run — nothing is inferred.
    """
    from .dispatcher import ScopeViolation, CeilingExceeded, RateLimited
    from .approval import ApprovalGate, ApprovalError
    from .tools.exploit import CommandExploit
    from .dispatcher import Dispatcher

    _require_auth(client, auth_ref)
    d = _eng_dir(client)
    d.mkdir(parents=True, exist_ok=True)
    gate = ApprovalGate(d)
    tool = CommandExploit()
    try:
        pending = tool.propose(
            target=target,
            engagement=client,
            dispatcher=Dispatcher(SCOPE),
            gate=gate,
            exploit_id=exploit_id,
            proposed_by=getpass.getuser(),
            params={"argv": list(command), "_reason": reason},
        )
    except (ScopeViolation, CeilingExceeded, RateLimited) as e:
        console.print(f"[red]rejected by dispatcher[/]: {e}")
        raise typer.Exit(1)
    except (ApprovalError, ValueError) as e:
        console.print(f"[red]cannot propose[/]: {e}")
        raise typer.Exit(1)
    console.print(f"[yellow]parked for approval[/] token=[bold]{pending.token}[/]")
    console.print(f"  {exploit_id} -> {target}")
    console.print(f"  cmd: {' '.join(pending.command)}")
    console.print(f"Next: [bold]fullcheck approve {client} --auth-ref {auth_ref}[/]")


@app.command(name="exploit-queue")
def exploit_queue(client: str):
    """List exploits awaiting human approval for this engagement."""
    from .approval import ApprovalGate

    d = _eng_dir(client)
    gate = ApprovalGate(d)
    pend = gate.pending()
    if not pend:
        console.print("[green]no pending exploits[/]")
        return
    t = Table(title=f"Pending exploits — {client}")
    t.add_column("token", overflow="fold")
    t.add_column("id"); t.add_column("target"); t.add_column("expires_in(s)")
    t.add_column("command", overflow="fold")
    import time as _t
    for p in pend:
        t.add_row(
            p.token, p.exploit_id, p.target,
            str(round(p.expires_at - _t.time(), 0)), " ".join(p.command),
        )
    console.print(t)


@app.command()
def approve(
    client: str,
    auth_ref: str = typer.Option(..., "--auth-ref"),
    operator: str = typer.Option("", "--operator", help="human confirming (audit)"),
):
    """Walk each pending exploit and record a per-exploit human decision.

    This IS the single human confirmation step. For every parked exploit you see
    the exact command and answer confirm/deny; confirming releases a single-use
    token that `exploit-run` consumes. Nothing here executes the exploit.
    """
    from .approval import ApprovalGate, ApprovalError

    _require_auth(client, auth_ref)
    operator = operator or getpass.getuser()
    d = _eng_dir(client)
    gate = ApprovalGate(d)
    pend = gate.pending()
    if not pend:
        console.print("[green]no pending exploits to review[/]")
        return
    console.print(
        f"[bold]{len(pend)} exploit(s)[/] pending — operator [bold]{operator}[/]\n"
    )
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
        console.print(f"Run them: [bold]fullcheck exploit-run {client} --auth-ref {auth_ref}[/]")


@app.command(name="exploit-run")
def exploit_run(
    client: str,
    auth_ref: str = typer.Option(..., "--auth-ref"),
    token: Optional[str] = typer.Option(
        None, "--token", help="run one confirmed token; omit to run all confirmed"
    ),
):
    """Execute human-confirmed exploits. Each token is single-use.

    Re-checks scope+ceiling at run time, consumes the approval token so it can
    never run twice, runs the exact approved command, and records stdout/stderr
    to the evidence chain (blast_radius=exploit).
    """
    from .approval import ApprovalGate, ApprovalError, ExploitStatus
    from .dispatcher import Dispatcher, ScopeViolation, CeilingExceeded, RateLimited
    from .evidence import Evidence
    from .tools.exploit import CommandExploit

    _require_auth(client, auth_ref)
    d = _eng_dir(client)
    gate = ApprovalGate(d)
    # Collect confirmed tokens (either the one named, or every confirmed record).
    all_recs = gate._read()  # noqa: SLF001 - CLI is inside the package
    if token:
        tokens = [token]
    else:
        tokens = [
            tk for tk, r in all_recs.items()
            if r.get("status") == ExploitStatus.CONFIRMED.value
        ]
    if not tokens:
        console.print("[yellow]no confirmed exploits to run[/] (approve some first).")
        raise typer.Exit(0)

    dispatcher = Dispatcher(SCOPE)
    evidence = Evidence(d, auth_ref)
    tool = CommandExploit()
    ran = 0
    for tk in tokens:
        try:
            res = tool.execute(
                token=tk,
                engagement=client,
                dispatcher=dispatcher,
                gate=gate,
                evidence=evidence,
            )
        except (ApprovalError, ScopeViolation, CeilingExceeded, RateLimited) as e:
            console.print(f"[red]skip[/] {tk[:12]}…: {e}")
            continue
        except Exception as e:  # noqa: BLE001
            console.print(f"[red]error[/] {tk[:12]}…: {e}")
            continue
        ran += 1
        console.print(
            f"[green]ran[/] {res.exploit_id} -> {res.action.target} "
            f"(exit {res.exit_code}) evidence={Path(res.artifact_path).name}"
        )
    console.print(f"[bold]{ran} exploit(s) executed[/].")


@app.command(name="intel-status")
def intel_status():
    """Report CVE cache + semantic-search readiness (GPU doctor)."""
    from .intel.embeddings import st_available, cuda_available, EmbeddingIndex, DEFAULT_MODEL

    t = Table(title="FullCheck intel status")
    t.add_column("check"); t.add_column("state")
    t.add_row("CVE cache", "present" if CVE_DB.exists() else "[yellow]missing[/]")
    t.add_row("sentence-transformers", "yes" if st_available() else "[yellow]no[/]")
    t.add_row("CUDA GPU", "yes" if cuda_available() else "[yellow]no (CPU)[/]")
    vec = EmbeddingIndex(CVE_DB)
    t.add_row("vector index", "built" if vec.exists() else "[yellow]not built[/]")
    active = CVE_DB.exists() and st_available() and vec.exists()
    t.add_row("search mode", "[green]semantic[/]" if active else "keyword (FTS5)")
    t.add_row("embed model", DEFAULT_MODEL)
    console.print(t)
    if not st_available():
        console.print(r"Enable semantic search: pip install -e '.\[embed]'")
    elif not vec.exists():
        console.print("Build the index: fullcheck build-embeddings")


if __name__ == "__main__":
    app()
