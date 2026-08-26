"""Offline smoke test: exercises dispatcher, evidence, report without recon binaries.
Run: python scripts/smoke_test.py
"""
from __future__ import annotations
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fullcheck.action import Action, BlastRadius, exceeds  # noqa: E402
from fullcheck.dispatcher import (  # noqa: E402
    Dispatcher, ScopeViolation, CeilingExceeded, RateLimited,
)
from fullcheck.evidence import Evidence  # noqa: E402
from fullcheck.report.generator import generate  # noqa: E402
from fullcheck.approval import (  # noqa: E402
    ApprovalGate, ApprovalError, ExploitStatus,
)
from fullcheck.tools.exploit import CommandExploit  # noqa: E402

PASS, FAIL = 0, 0


def check(name: str, cond: bool):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}")


def main():
    tmp = Path(tempfile.mkdtemp(prefix="fullcheck_smoke_"))
    scope = tmp / "scope.yaml"
    scope.write_text(
        """
engagements:
  acme:
    auth_ref: "ACME-001"
    ceiling: "scan"
    scope:
      - "acme.com"
      - "*.acme.com"
    out_of_scope:
      - "billing.acme.com"
  tiny:
    auth_ref: "TINY-001"
    ceiling: "probe"
    scope:
      - "tiny.com"
rate_limits:
  requests_per_second_per_host: 3
"""
    )
    disp = Dispatcher(scope)

    print("[blast-radius ordering]")
    check("scan exceeds probe", exceeds(BlastRadius.SCAN, BlastRadius.PROBE))
    check("passive under scan", not exceeds(BlastRadius.PASSIVE, BlastRadius.SCAN))

    print("[scope enforcement]")
    ok = Action(tool="httpx", target="www.acme.com", blast_radius=BlastRadius.PROBE,
                engagement="acme")
    try:
        disp.check(ok); check("in-scope wildcard allowed", True)
    except Exception as e:
        check(f"in-scope wildcard allowed ({e})", False)

    oos = Action(tool="httpx", target="evil.com", blast_radius=BlastRadius.PROBE,
                 engagement="acme")
    try:
        disp.check(oos); check("out-of-scope rejected", False)
    except ScopeViolation:
        check("out-of-scope rejected", True)

    explicit_oos = Action(tool="httpx", target="billing.acme.com",
                          blast_radius=BlastRadius.PROBE, engagement="acme")
    try:
        disp.check(explicit_oos); check("explicit out_of_scope rejected", False)
    except ScopeViolation:
        check("explicit out_of_scope rejected", True)

    print("[ceiling enforcement]")
    over = Action(tool="nuclei", target="tiny.com", blast_radius=BlastRadius.EXPLOIT,
                  engagement="tiny")
    try:
        disp.check(over); check("exploit over probe-ceiling rejected", False)
    except CeilingExceeded:
        check("exploit over probe-ceiling rejected", True)

    print("[unknown engagement]")
    unk = Action(tool="httpx", target="acme.com", engagement="ghost")
    try:
        disp.check(unk); check("unknown engagement rejected", False)
    except ScopeViolation:
        check("unknown engagement rejected", True)

    print("[rate limiting]")
    rl_hits = 0
    for _ in range(6):
        a = Action(tool="httpx", target="tiny.com", blast_radius=BlastRadius.PROBE,
                   engagement="tiny")
        try:
            disp.check(a)
        except RateLimited:
            rl_hits += 1
    check("rate limit fires after burst", rl_hits > 0)

    print("[evidence chain]")
    eng_dir = tmp / "engagements" / "acme"
    ev = Evidence(eng_dir, "ACME-001")
    a = Action(tool="httpx", target="www.acme.com", blast_radius=BlastRadius.PROBE,
               engagement="acme")
    art = ev.record(a, b'{"status":200}', b"", 0, "www.acme.com")
    check("artifact written", art.exists())
    manifest = (eng_dir / "evidence" / "manifest.json")
    check("manifest written", manifest.exists())
    check("manifest has auth_ref", "ACME-001" in manifest.read_text())
    check("manifest has sha256", "sha256" in manifest.read_text())

    print("[report generation]")
    findings = [
        {"title": "Exposed .git directory", "severity": "high", "confidence": "high",
         "asset": "www.acme.com", "evidence_artifact": "raw/x.json",
         "cve": [], "summary": "The .git dir is downloadable.",
         "remediation": "Block access to .git."},
        {"title": "Missing DMARC", "severity": "medium", "confidence": "high",
         "asset": "acme.com", "evidence_artifact": "raw/y.json", "cve": [],
         "summary": "No DMARC record.", "remediation": "Publish DMARC p=reject."},
    ]
    rpt = generate(eng_dir, "ACME", "acme", "ACME-001", ["acme.com"], findings)
    body = rpt.read_text()
    check("report written", rpt.exists())
    check("report has exec summary", "Executive summary" in body)
    check("report counts high=1", "| High     | 1 |" in body)
    check("report severity-sorted (high before medium)",
          body.index("Exposed .git") < body.index("Missing DMARC"))

    print("[exploit approval gate]")
    # A separate scope with an exploit-ceiling engagement and a high rate cap so
    # the many dispatcher checks below don't trip the rate limiter.
    scope2 = tmp / "scope2.yaml"
    scope2.write_text(
        """
engagements:
  acme:
    auth_ref: "ACME-001"
    ceiling: "scan"
    scope: ["*.acme.com", "acme.com"]
  pwn:
    auth_ref: "PWN-001"
    ceiling: "exploit"
    scope: ["lab.internal", "10.0.0.0/24"]
rate_limits:
  requests_per_second_per_host: 1000
"""
    )
    disp2 = Dispatcher(scope2)
    xtool = CommandExploit()
    xdir = tmp / "engagements" / "pwn"
    gate = ApprovalGate(xdir)

    # Gate 1: an exploit against a scan-ceiling engagement is rejected at propose
    try:
        xtool.propose(target="www.acme.com", engagement="acme", dispatcher=disp2,
                      gate=gate, exploit_id="X", proposed_by="t",
                      params={"argv": ["echo", "hi"]})
        check("exploit blocked by scan ceiling", False)
    except CeilingExceeded:
        check("exploit blocked by scan ceiling", True)

    # propose parks a PENDING record and does NOT execute
    pend = xtool.propose(
        target="lab.internal", engagement="pwn", dispatcher=disp2, gate=gate,
        exploit_id="CVE-TEST", proposed_by="worker",
        params={"argv": [sys.executable, "-c", "print('pwned')"],
                "_reason": "authorized lab"},
    )
    check("propose returns a token", bool(pend.token))
    check("proposed status is pending", pend.status == ExploitStatus.PENDING.value)
    check("one pending in queue", len(gate.pending()) == 1)

    ev2 = Evidence(xdir, "PWN-001")
    # execute before any human confirmation must be refused and never run
    try:
        xtool.execute(token=pend.token, engagement="pwn", dispatcher=disp2,
                      gate=gate, evidence=ev2)
        check("execute before confirm blocked", False)
    except ApprovalError:
        check("execute before confirm blocked", True)

    # confirm, then execute runs exactly once
    gate.decide(pend.token, confirm=True, decided_by="will")
    res = xtool.execute(token=pend.token, engagement="pwn", dispatcher=disp2,
                        gate=gate, evidence=ev2)
    check("confirmed exploit runs", res.exit_code == 0)
    check("exploit stdout captured", b"pwned" in res.stdout)
    check("exploit recorded to evidence", Path(res.artifact_path).exists())

    # single-use: the same token cannot run a second time
    try:
        xtool.execute(token=pend.token, engagement="pwn", dispatcher=disp2,
                      gate=gate, evidence=ev2)
        check("token single-use enforced", False)
    except ApprovalError:
        check("token single-use enforced", True)

    # deny path: a denied exploit never runs
    pd = xtool.propose(target="lab.internal", engagement="pwn", dispatcher=disp2,
                       gate=gate, exploit_id="CVE-TEST-2", proposed_by="worker",
                       params={"argv": [sys.executable, "-c", "print('nope')"]})
    gate.decide(pd.token, confirm=False, decided_by="will")
    try:
        xtool.execute(token=pd.token, engagement="pwn", dispatcher=disp2,
                      gate=gate, evidence=ev2)
        check("denied exploit never runs", False)
    except ApprovalError:
        check("denied exploit never runs", True)

    # a read-only action can never enter the approval queue
    try:
        gate.propose(
            action=Action(tool="httpx", target="lab.internal",
                          blast_radius=BlastRadius.PROBE, engagement="pwn"),
            command=["echo"], exploit_id="bad", proposed_by="t",
        )
        check("read-only action rejected from queue", False)
    except ApprovalError:
        check("read-only action rejected from queue", True)

    # a decision must carry a human identity
    p3 = xtool.propose(target="lab.internal", engagement="pwn", dispatcher=disp2,
                       gate=gate, exploit_id="CVE-TEST-3", proposed_by="worker",
                       params={"argv": [sys.executable, "-c", "print(1)"]})
    try:
        gate.decide(p3.token, confirm=True, decided_by="")
        check("decide requires operator identity", False)
    except ApprovalError:
        check("decide requires operator identity", True)

    # expiry: a short-TTL proposal (isolated queue) drops out and can't be confirmed
    egate = ApprovalGate(tmp / "engagements" / "pwn_exp", ttl_seconds=0.05)
    ep = xtool.propose(target="lab.internal", engagement="pwn", dispatcher=disp2,
                       gate=egate, exploit_id="CVE-EXP", proposed_by="worker",
                       params={"argv": [sys.executable, "-c", "print(1)"]})
    time.sleep(0.08)
    check("expired proposal leaves pending queue", len(egate.pending()) == 0)
    try:
        egate.decide(ep.token, confirm=True, decided_by="will")
        check("cannot confirm expired proposal", False)
    except ApprovalError:
        check("cannot confirm expired proposal", True)

    check("audit log written", (xdir / "exploit_audit.jsonl").exists())

    print(f"\n{'='*40}\n  {PASS} passed, {FAIL} failed\n{'='*40}")
    print(f"artifacts: {tmp}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
