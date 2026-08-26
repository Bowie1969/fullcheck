"""Offline smoke test for the M365/Entra module (v0.2).

Proves the safety-critical logic without touching the network or needing msal:

  1. an M365Probe runs through the spine — Dispatcher.check + Evidence.record;
  2. the Dispatcher gates the SCAN tier below a probe-ceiling engagement;
  3. analyze rules are deterministic and fire on synthetic Graph artifacts;
  4. a `stub` technique refuses to propose (cannot be queued);
  5. a FLOOR technique is rejected against a scan-ceiling engagement (needs exploit),
     and parks a token (no execution) against an exploit-ceiling one.

Run:  python scripts/m365_smoke_test.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from fullcheck.action import BlastRadius  # noqa: E402
from fullcheck.approval import ApprovalError, ApprovalGate  # noqa: E402
from fullcheck.dispatcher import CeilingExceeded, Dispatcher  # noqa: E402
from fullcheck.evidence import Evidence  # noqa: E402
from fullcheck.m365 import analyze as m_analyze  # noqa: E402
from fullcheck.m365 import catalog as m_cat  # noqa: E402
from fullcheck.m365.base import M365Probe, register_probe  # noqa: E402

_fails = 0


def check(label: str, cond: bool) -> None:
    global _fails
    print(("  [ok]  " if cond else "  [FAIL]") + " " + label)
    if not cond:
        _fails += 1


tmp = Path(tempfile.mkdtemp(prefix="fullcheck_m365_"))
scope = tmp / "scope.yaml"
scope.write_text(
    """
engagements:
  cloudco:
    auth_ref: "CLOUD-001"
    ceiling: "scan"
    scope: ["contoso.com", "*.contoso.com"]
  cloudco-probe:
    auth_ref: "CLOUD-P"
    ceiling: "probe"
    scope: ["probe.com"]
  cloudco-x:
    auth_ref: "CLOUD-X"
    ceiling: "exploit"
    scope: ["pwn.com"]
rate_limits:
  requests_per_second_per_host: 1000
"""
)
disp = Dispatcher(scope)


# 1. a probe runs through the spine without any network I/O
class _FakeProbe(M365Probe):
    name = "m365-fake"
    blast_radius = BlastRadius.PASSIVE

    def collect(self, domain, params, http):
        return {"domain": domain, "ok": True}


eng_dir = tmp / "engagements" / "cloudco"
ev = Evidence(eng_dir, "CLOUD-001")
res = _FakeProbe().run("contoso.com", "cloudco", disp, ev, params={}, http="unused")
check("probe records an evidence artifact", Path(res.artifact_path).exists())
check("probe artifact carries the collected payload",
      json.loads(Path(res.artifact_path).read_text())["stdout"].find("\"ok\"") != -1)
manifest = eng_dir / "evidence" / "manifest.json"
check("probe artifact in manifest with auth_ref", "CLOUD-001" in manifest.read_text())

# scope enforcement: out-of-scope domain is rejected
try:
    _FakeProbe().run("evil.com", "cloudco", disp, ev, params={}, http="unused")
    check("out-of-scope domain rejected", False)
except Exception as e:  # ScopeViolation
    check("out-of-scope domain rejected", "not in scope" in str(e))


# 2. SCAN gated below a probe ceiling
from fullcheck.m365.graph import run_scan, GraphCreds  # noqa: E402
from fullcheck.m365.graph import GraphCheck  # noqa: E402

pe_dir = tmp / "engagements" / "cloudco-probe"
scan_summary = run_scan(
    domain="probe.com", engagement="cloudco-probe", engagement_dir=pe_dir,
    dispatcher=disp, evidence=Evidence(pe_dir, "CLOUD-P"),
    creds=GraphCreds(tenant_id="t", client_id="c", client_secret="s"),
    checks=[GraphCheck(key="ca-policies", path="/x")],
    log=lambda m: None,
)
check("SCAN denied under probe ceiling (no token acquired)",
      len(scan_summary["ran"]) == 0 and len(scan_summary["skipped"]) == 1)


# 3. analyze rules are deterministic over synthetic artifacts
def _write_artifact(dirpath: Path, tool: str, target: str, payload: dict) -> None:
    dirpath.mkdir(parents=True, exist_ok=True)
    blob = {"action": {"tool": tool, "target": target}, "stdout": json.dumps(payload)}
    (dirpath / f"20260101T000000Z_{tool}_{target}.json").write_text(json.dumps(blob))


raw = tmp / "engagements" / "an" / "raw"
_write_artifact(raw, "m365-userrealm", "contoso.com",
                {"is_federated": True, "auth_url": "https://adfs.contoso.com/adfs/ls/",
                 "federation_brand": "Contoso"})
_write_artifact(raw, "graph-ca-policies", "contoso.com",
                {"value": [{"displayName": "Legacy", "state": "enabled",
                            "grantControls": {"builtInControls": ["block"]}}]})
_write_artifact(raw, "graph-security-defaults", "contoso.com", {"isEnabled": False})
_write_artifact(raw, "graph-directory-roles", "contoso.com",
                {"value": [{"displayName": "Global Administrator",
                            "members": [{"id": str(i)} for i in range(7)]}]})
_write_artifact(raw, "graph-mfa-registration", "contoso.com",
                {"value": [{"isMfaRegistered": False}, {"isMfaRegistered": True},
                           {"isMfaRegistered": False}, {"isMfaRegistered": False}]})

findings = m_analyze.analyze(raw, "contoso.com", log=lambda m: None)
titles = " | ".join(f["title"] for f in findings)
check("analyze: federated/ADFS finding", "federated" in titles.lower())
check("analyze: no-MFA CA finding", "no enabled conditional access policy requires mfa" in titles.lower())
check("analyze: excessive Global Admins finding", "excessive global administrators" in titles.lower())
check("analyze: users-without-MFA finding", "no mfa method registered" in titles.lower())
check("analyze: deterministic (same result twice)",
      [f["title"] for f in findings] == [f["title"] for f in m_analyze.analyze(raw, "contoso.com", log=lambda m: None)])
check("analyze: every finding cites an artifact",
      all(f.get("evidence_artifact", "").startswith("raw/") for f in findings))

# security-defaults-off + zero enabled CA fires only with its own (bare) tenant
raw2 = tmp / "engagements" / "an2" / "raw"
_write_artifact(raw2, "graph-ca-policies", "bare.com", {"value": []})
_write_artifact(raw2, "graph-security-defaults", "bare.com", {"isEnabled": False})
f2 = " | ".join(f["title"] for f in m_analyze.analyze(raw2, "bare.com", log=lambda m: None))
check("analyze: security-defaults + no CA finding (bare tenant)", "neither security defaults" in f2.lower())


# 4. a stub technique refuses to propose (cannot be queued)
m_cat.load_techniques()
xe_dir = tmp / "engagements" / "cloudco-x"
gate = ApprovalGate(xe_dir)
spray = m_cat.get("m365-password-spray")
check("password-spray is a stub", spray.stub is True)
try:
    spray.propose(target="pwn.com", engagement="cloudco-x", dispatcher=disp, gate=gate,
                  exploit_id="m365-password-spray", proposed_by="t", params={})
    check("stub technique refuses to propose", False)
except NotImplementedError:
    check("stub technique refuses to propose", True)


# 5. FLOOR technique needs exploit ceiling; a non-stub wired technique parks a token
class _WiredTech(m_cat.M365Technique):
    name = "m365-test-wired"
    blast_radius = BlastRadius.EXPLOIT
    stub = False
    risk = "test only"

    def _build(self, target, params):
        return ["echo", "would-attack", target]


wired = _WiredTech()
# against the scan-ceiling engagement: dispatcher rejects (needs exploit)
try:
    wired.propose(target="contoso.com", engagement="cloudco", dispatcher=disp, gate=gate,
                  exploit_id="m365-test-wired", proposed_by="t", params={})
    check("FLOOR technique rejected under scan ceiling", False)
except CeilingExceeded:
    check("FLOOR technique rejected under scan ceiling", True)
# against the exploit-ceiling engagement: parks a token, does not execute
pending = wired.propose(target="pwn.com", engagement="cloudco-x", dispatcher=disp, gate=gate,
                        exploit_id="m365-test-wired", proposed_by="t", params={"_reason": "authorized"})
check("wired FLOOR technique parks a token (no execution)",
      bool(pending.token) and len(gate.pending()) == 1)
check("parked command is the built argv", pending.command == ["echo", "would-attack", "pwn.com"])

print()
if _fails:
    print(f"FAILED: {_fails} check(s)")
    sys.exit(1)
print("all M365 smoke checks passed")
