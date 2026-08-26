from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Callable
from .dispatcher import Dispatcher, ScopeViolation, CeilingExceeded, RateLimited
from .evidence import Evidence
from .tools.recon import RECON_PIPELINE
from .intel.cve_cache import CveCache


def run_recon(
    engagement: str,
    targets: list[str],
    engagement_dir: Path,
    auth_ref: str,
    scope_path: Path,
    log: Callable[[str], None] = print,
) -> dict[str, Any]:
    """Execute the recon pipeline over targets. Every call goes through dispatch."""
    dispatcher = Dispatcher(scope_path)
    evidence = Evidence(engagement_dir, auth_ref)
    summary: dict[str, Any] = {"ran": [], "skipped": [], "errors": []}

    for tool in RECON_PIPELINE:
        if not tool.available():
            log(f"  [skip] {tool.name}: binary not on PATH")
            summary["skipped"].append({"tool": tool.name, "why": "not installed"})
            continue
        for target in targets:
            try:
                res = tool.run(
                    target=target,
                    engagement=engagement,
                    dispatcher=dispatcher,
                    evidence=evidence,
                )
                log(f"  [ok]   {tool.name} -> {target} (exit {res.exit_code})")
                summary["ran"].append(
                    {"tool": tool.name, "target": target, "exit": res.exit_code}
                )
            except (ScopeViolation, CeilingExceeded) as e:
                log(f"  [DENY] {tool.name} -> {target}: {e}")
                summary["skipped"].append(
                    {"tool": tool.name, "target": target, "why": str(e)}
                )
            except RateLimited as e:
                log(f"  [rate] {tool.name} -> {target}: {e}")
                summary["skipped"].append(
                    {"tool": tool.name, "target": target, "why": str(e)}
                )
            except Exception as e:  # noqa: BLE001 - keep pipeline alive
                log(f"  [err]  {tool.name} -> {target}: {e}")
                summary["errors"].append(
                    {"tool": tool.name, "target": target, "error": str(e)}
                )
    return summary


def correlate_cves(
    raw_dir: Path, cve_db: Path, log: Callable[[str], None] = print
) -> dict[str, list[dict]]:
    """Pull tech fingerprints out of httpx output and match CVEs."""
    if not cve_db.exists():
        log("  [skip] CVE cache not built; run `fullcheck update-intel`")
        return {}
    cache = CveCache(cve_db)
    matches: dict[str, list[dict]] = {}
    for artifact in raw_dir.glob("*httpx*.json"):
        try:
            blob = json.loads(artifact.read_text())
        except json.JSONDecodeError:
            continue
        for line in blob.get("stdout", "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            techs = rec.get("tech") or rec.get("technologies") or []
            for tech in techs:
                found = cache.cves_for_tech(tech)
                if found:
                    matches.setdefault(tech, [])
                    for cve in found:
                        if cve not in matches[tech]:
                            matches[tech].append(cve)
    return matches
