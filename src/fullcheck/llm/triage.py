from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from .client import OpenClawClient

_PROMPT = (Path(__file__).parent / "triage_prompt.txt").read_text()


def build_user_payload(
    raw_dir: Path, cve_matches: dict[str, list[dict]], max_chars: int = 40000
) -> str:
    """Collate raw artifacts + CVE matches into one bounded prompt payload."""
    chunks: list[str] = []
    for artifact in sorted(raw_dir.glob("*.json")):
        try:
            blob = json.loads(artifact.read_text())
        except json.JSONDecodeError:
            continue
        stdout = blob.get("stdout", "")
        if not stdout.strip():
            continue
        rel = artifact.name
        chunks.append(
            f"### artifact: raw/{rel}\n"
            f"tool: {blob.get('action', {}).get('tool')}\n"
            f"target: {blob.get('action', {}).get('target')}\n"
            f"output:\n{stdout[:6000]}\n"
        )
    cve_block = json.dumps(cve_matches, indent=2)[:8000] if cve_matches else "{}"
    body = "\n".join(chunks)
    if len(body) > max_chars:
        body = body[:max_chars] + "\n...[truncated]"
    return f"## RECON OUTPUT\n{body}\n\n## MATCHED CVES\n{cve_block}"


def triage(
    raw_dir: Path,
    cve_matches: dict[str, list[dict]],
    client: OpenClawClient | None = None,
) -> list[dict[str, Any]]:
    client = client or OpenClawClient()
    user = build_user_payload(raw_dir, cve_matches)
    result = client.chat_json(_PROMPT, user)
    if not isinstance(result, list):
        raise ValueError("triage did not return a JSON array")
    return result
