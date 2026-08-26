"""Turn raw M365 recon + Graph artifacts into report findings — deterministically.

FullCheck's LLM triage prompt forbids inventing findings; for structured Graph
data we go one better and don't involve the LLM at all. Findings here come from
explicit, auditable RULES over the raw artifacts the recon/scan steps wrote to
the evidence chain. Each rule reads the parsed artifacts and yields zero or more
findings in the report schema (see report/template.md.j2):

    {
      "title": str, "severity": critical|high|medium|low|info,
      "confidence": high|medium|low, "asset": str (tenant/domain),
      "evidence_artifact": "raw/<file>.json", "cve": [], "summary": str,
      "remediation": str,
    }

A rule is `fn(ctx: AnalyzeContext) -> list[dict]`, registered with @rule. Rules
are filled by analyze_rules.py. Keeping them as small pure functions over a
shared parsed context means an agent can add coverage by appending one function,
and every finding is traceable to the artifact that justifies it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

Finding = dict[str, Any]
Rule = Callable[["AnalyzeContext"], list[Finding]]

RULES: list[Rule] = []


def rule(fn: Rule) -> Rule:
    RULES.append(fn)
    return fn


def load_rules() -> list[Rule]:
    from . import analyze_rules as _  # noqa: F401 — import populates RULES

    return RULES


@dataclass
class Artifact:
    """A parsed raw evidence artifact plus the recovered tool payload."""

    path: Path
    tool: str
    target: str
    payload: Any  # the JSON that the probe/check stored as its stdout

    @property
    def rel(self) -> str:
        return f"raw/{self.path.name}"


@dataclass
class AnalyzeContext:
    """Everything a rule needs: the tenant/domain and the parsed artifacts.

    Helpers `recon(name_substr)` and `graph(key)` fetch the artifact(s) a rule
    cares about without every rule re-globbing the directory.
    """

    domain: str
    artifacts: list[Artifact] = field(default_factory=list)

    def by_tool(self, substr: str) -> list[Artifact]:
        return [a for a in self.artifacts if substr in a.tool]

    def recon(self, name_substr: str) -> list[Artifact]:
        return [a for a in self.artifacts if a.tool.startswith("m365-") and name_substr in a.tool]

    def graph(self, key: str) -> Artifact | None:
        want = f"graph-{key}"
        for a in self.artifacts:
            if a.tool == want:
                return a
        return None


def _load_artifacts(raw_dir: Path, domain: str) -> list[Artifact]:
    """Parse the m365-* and graph-* evidence artifacts for this tenant."""
    out: list[Artifact] = []
    for f in sorted(raw_dir.glob("*.json")):
        try:
            blob = json.loads(f.read_text())
        except json.JSONDecodeError:
            continue
        action = blob.get("action", {})
        tool = action.get("tool", "")
        if not (tool.startswith("m365-") or tool.startswith("graph-")):
            continue
        if action.get("target") not in (domain, "") and domain:
            # keep only artifacts for the tenant under analysis
            if action.get("target") != domain:
                continue
        # the probe/check stored its JSON payload as the artifact "stdout"
        raw_stdout = blob.get("stdout", "")
        try:
            payload = json.loads(raw_stdout) if raw_stdout else {}
        except json.JSONDecodeError:
            payload = {"_raw": raw_stdout}
        out.append(Artifact(path=f, tool=tool, target=action.get("target", ""), payload=payload))
    return out


def analyze(raw_dir: Path, domain: str, log: Callable[[str], None] = print) -> list[Finding]:
    """Apply every registered rule over the tenant's artifacts. Deterministic."""
    ctx = AnalyzeContext(domain=domain, artifacts=_load_artifacts(Path(raw_dir), domain))
    findings: list[Finding] = []
    for r in load_rules():
        try:
            produced = r(ctx) or []
        except Exception as e:  # noqa: BLE001 — a broken rule must not sink analysis
            log(f"  [rule-error] {getattr(r, '__name__', r)}: {e}")
            continue
        for f in produced:
            f.setdefault("asset", domain)
            f.setdefault("cve", [])
            f.setdefault("confidence", "medium")
            findings.append(f)
    return findings
