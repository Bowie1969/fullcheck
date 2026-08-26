"""Offline smoke test for FullCheck-Internal.

Proves the safety-critical logic without touching a network or needing any
pentest binary installed:

  1. the catalog populates and gate classes are what we expect;
  2. the autonomy router GATEs every FLOOR technique in every mode, and only
     AUTO-runs CEILING techniques where the mode allows;
  3. `run_auto` defensively refuses a FLOOR technique even if called directly;
  4. the Dispatcher's per-CIDR zone_ceilings cap a subnet below the engagement
     ceiling (and are backward-compatible when absent);
  5. the gated propose path parks a token (no execution).

Run:  python scripts/internal_smoke_test.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# Make the package importable without an install.
SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from fullcheck.action import Action, BlastRadius  # noqa: E402
from fullcheck.approval import ApprovalError, ApprovalGate  # noqa: E402
from fullcheck.dispatcher import CeilingExceeded, Dispatcher  # noqa: E402
from fullcheck.internal import catalog as cat  # noqa: E402
from fullcheck.internal.autonomy import Decision, decide  # noqa: E402
from fullcheck.internal.tools import exploit as _exploit  # noqa: E402,F401 populate catalog

PASS, FAIL = "  [ok]  ", "  [FAIL]"
_fails = 0


def check(label: str, cond: bool) -> None:
    global _fails
    print((PASS if cond else FAIL) + " " + label)
    if not cond:
        _fails += 1


# 1. catalog populated, classes as expected
check("catalog loaded techniques", len(cat.CATALOG) >= 6)
check("web-file-read is CEILING", cat.CATALOG["web-file-read"].gate_class is cat.GateClass.CEILING)
check("password-spray is FLOOR", cat.CATALOG["password-spray"].gate_class is cat.GateClass.FLOOR)
check("secretsdump is FLOOR + post_exploit",
      cat.CATALOG["secretsdump"].gate_class is cat.GateClass.FLOOR
      and cat.CATALOG["secretsdump"].blast_radius is BlastRadius.POST_EXPLOIT)
check("InternalExploit default class is FLOOR (default-deny)",
      cat.InternalExploit.gate_class is cat.GateClass.FLOOR)

# 2. autonomy routing
spray = cat.get("password-spray")
webread = cat.get("web-file-read")
spray_action = spray._action("10.0.0.5", "eng", {})
web_action = webread._action("10.0.0.5", "eng", {})

for mode in ("gated", "auto_low", "aggressive"):
    check(f"FLOOR gated in mode={mode}", decide(mode, spray, spray_action) is Decision.GATE)
check("CEILING auto in aggressive", decide("aggressive", webread, web_action) is Decision.AUTO)
check("CEILING(low_risk) auto in auto_low", decide("auto_low", webread, web_action) is Decision.AUTO)
check("CEILING gated in gated", decide("gated", webread, web_action) is Decision.GATE)

# 3. run_auto refuses FLOOR even when called directly (dispatcher/evidence unused)
try:
    spray.run_auto("10.0.0.5", "eng", dispatcher=None, evidence=None, params={"users": "u", "password": "p"})
    check("run_auto refuses FLOOR", False)
except ApprovalError:
    check("run_auto refuses FLOOR", True)

# 4. per-CIDR zone_ceilings
tmp = Path(tempfile.mkdtemp())
scope = tmp / "scope.yaml"
scope.write_text(
    "engagements:\n"
    "  eng:\n"
    "    auth_ref: REF\n"
    "    ceiling: post_exploit\n"
    "    scope: [10.0.0.0/16]\n"
    "    zone_ceilings:\n"
    "      - cidr: 10.0.20.0/24\n"
    "        ceiling: probe\n"
    "rate_limits:\n"
    "  requests_per_second_per_host: 1000\n"
)
disp = Dispatcher(scope)
# EXPLOIT against a normal in-scope host: allowed
try:
    disp.check(Action(tool="t", target="10.0.5.5", blast_radius=BlastRadius.EXPLOIT, engagement="eng"))
    check("EXPLOIT allowed outside capped zone", True)
except CeilingExceeded:
    check("EXPLOIT allowed outside capped zone", False)
# EXPLOIT against the OT zone capped at probe: denied
try:
    disp.check(Action(tool="t", target="10.0.20.9", blast_radius=BlastRadius.EXPLOIT, engagement="eng"))
    check("EXPLOIT denied inside probe-capped zone", False)
except CeilingExceeded:
    check("EXPLOIT denied inside probe-capped zone", True)
# PROBE against the OT zone: allowed (still discoverable)
try:
    disp.check(Action(tool="t", target="10.0.20.9", blast_radius=BlastRadius.PROBE, engagement="eng"))
    check("PROBE still allowed inside capped zone", True)
except CeilingExceeded:
    check("PROBE still allowed inside capped zone", False)

# 5. gated propose parks a token (no execution)
eng_dir = tmp / "engagements" / "eng"
gate = ApprovalGate(eng_dir)
pending = spray.propose(
    target="10.0.5.5", engagement="eng", dispatcher=disp, gate=gate,
    exploit_id="password-spray", proposed_by="smoke",
    params={"users": "users.txt", "password": "X", "_reason": "test"},
)
check("propose parked a token", bool(pending.token) and len(gate.pending()) == 1)
check("parked command is the built argv", "nxc" in pending.command and "--continue-on-success" in pending.command)

print()
if _fails:
    print(f"FAILED: {_fails} check(s)")
    sys.exit(1)
print("all internal smoke checks passed")
