from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from jinja2 import Environment, FileSystemLoader, select_autoescape
from .. import __version__

_TEMPLATE_DIR = Path(__file__).parent
_SEVERITIES = ["critical", "high", "medium", "low", "info"]


def _counts(findings: list[dict]) -> dict[str, int]:
    c = {s: 0 for s in _SEVERITIES}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        if sev in c:
            c[sev] += 1
    return c


def _sort_key(f: dict) -> int:
    order = {s: i for i, s in enumerate(_SEVERITIES)}
    return order.get(str(f.get("severity", "info")).lower(), 99)


def generate(
    engagement_dir: Path,
    client: str,
    engagement: str,
    auth_ref: str,
    scope: list[str],
    findings: list[dict[str, Any]],
    out_name: str = "report.md",
) -> Path:
    findings = sorted(findings, key=_sort_key)
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(enabled_extensions=()),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    tmpl = env.get_template("template.md.j2")
    md = tmpl.render(
        client=client,
        engagement=engagement,
        auth_ref=auth_ref,
        scope=scope,
        version=__version__,
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        counts=_counts(findings),
        findings=findings,
    )
    out = Path(engagement_dir) / out_name
    out.write_text(md, encoding="utf-8")
    return out
