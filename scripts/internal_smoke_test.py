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
from fullcheck.internal.autonomy import Decision, decide, is_owned_lab  # noqa: E402
from fullcheck.internal.tools import exploit as _exploit  # noqa: E402,F401 populate catalog
from fullcheck.internal import planner  # noqa: E402
from fullcheck.internal.autochain import run_autochain  # noqa: E402


class _StubLlm:
    """Stand-in OpenClaw client: returns canned planner output, hits no network."""

    def __init__(self, steps):
        self._steps = steps

    def chat_json(self, system, user):  # noqa: D401 - matches OpenClawClient
        return self._steps

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

# 2b. auto_lab: floor lowers ONLY for an attested owned lab; fail-safe otherwise
check("is_owned_lab: flag + SELF- auth ⇒ True",
      is_owned_lab({"owned_lab": True, "auth_ref": "SELF-LAB-20260826-001"}) is True)
check("is_owned_lab: missing flag ⇒ False",
      is_owned_lab({"auth_ref": "SELF-LAB-1"}) is False)
check("is_owned_lab: non-SELF auth_ref ⇒ False (client can't qualify)",
      is_owned_lab({"owned_lab": True, "auth_ref": "NPT-ACME-001"}) is False)
check("auto_lab AUTO-fires FLOOR on attested owned lab",
      decide("auto_lab", spray, spray_action, owned_lab=True) is Decision.AUTO)
check("auto_lab AUTO-fires post-exploit FLOOR on attested owned lab",
      decide("auto_lab", cat.get("secretsdump"),
             cat.get("secretsdump")._action("10.0.0.5", "eng", {}), owned_lab=True) is Decision.AUTO)
check("auto_lab UNATTESTED fails safe to gated (FLOOR parked)",
      decide("auto_lab", spray, spray_action, owned_lab=False) is Decision.GATE)

# 3. run_auto refuses FLOOR even when called directly (dispatcher/evidence unused)
try:
    spray.run_auto("10.0.0.5", "eng", dispatcher=None, evidence=None, params={"users": "u", "password": "p"})
    check("run_auto refuses FLOOR", False)
except ApprovalError:
    check("run_auto refuses FLOOR", True)
# 3b. run_auto STILL refuses FLOOR without the owned-lab attestation (default-safe)
try:
    spray.run_auto("10.0.0.5", "eng", dispatcher=None, evidence=None,
                   params={"users": "u", "password": "p"}, owned_lab=False)
    check("run_auto refuses FLOOR when owned_lab=False", False)
except ApprovalError:
    check("run_auto refuses FLOOR when owned_lab=False", True)

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

# 6. planner output validation is the trust boundary: catalog-bound, drops junk,
#    and the LLM can never set impact/gating fields.
menu = planner.technique_menu()
check("technique_menu built from catalog", len(menu) == len(cat.CATALOG))
check("menu carries param hints", any(m["params"] for m in menu))
raw_steps = [
    {"technique": "web-file-read", "target": "10.0.0.5", "params": {"url": "http://x/etc/passwd"}},
    {"technique": "totally-made-up", "target": "10.0.0.5"},          # unknown -> dropped
    {"technique": "password-spray", "target": ""},                    # blank target -> dropped
    {"technique": "secretsdump", "target": "10.0.0.9",
     "params": {"creds": "d/u:p@h", "blast_radius": "passive", "gate_class": "ceiling"}},
]
valid = planner.validate_steps(raw_steps, max_steps=10)
check("validate_steps keeps only catalog-valid, non-blank steps", len(valid) == 2)
check("validate_steps drops unknown technique",
      all(s.technique in cat.CATALOG for s in valid))
sd = next(s for s in valid if s.technique == "secretsdump")
check("validate_steps strips model-set impact/gating fields",
      "blast_radius" not in sd.params and "gate_class" not in sd.params and sd.params.get("creds") == "d/u:p@h")
check("validate_steps honours max_steps cap",
      len(planner.validate_steps([{"technique": "web-file-read", "target": "h", "params": {"url": "u"}}] * 5, max_steps=2)) == 2)
check("_coerce_steps unwraps {'steps': [...]}",
      planner._coerce_steps({"steps": [{"technique": "x", "target": "y"}]}) == [{"technique": "x", "target": "y"}])
check("_coerce_steps rejects a bare object", planner._coerce_steps({"nope": 1}) == [])

# 7. autochain end-to-end WITHOUT an owned-lab attestation: the LLM proposes a
#    FLOOR technique and the chain PARKS it for a human — nothing auto-executes.
lab_tmp = Path(tempfile.mkdtemp())
lab_scope = lab_tmp / "scope.yaml"
lab_scope.write_text(
    "engagements:\n"
    "  eng:\n"
    "    auth_ref: NPT-CLIENT-001\n"       # NOT a SELF-* ref
    "    ceiling: post_exploit\n"
    "    autonomy: auto_lab\n"             # mislabeled auto_lab on a client -> must fail safe
    "    scope: [10.0.0.0/16]\n"
    "rate_limits:\n"
    "  requests_per_second_per_host: 1000\n"
)
import yaml as _yaml  # noqa: E402

lab_eng = _yaml.safe_load(lab_scope.read_text())["engagements"]["eng"]
check("autochain test engagement is NOT an owned lab", is_owned_lab(lab_eng) is False)
lab_eng_dir = lab_tmp / "engagements" / "eng"
stub = _StubLlm([
    {"technique": "password-spray", "target": "10.0.5.5",
     "params": {"users": "users.txt", "password": "Autumn2026!"}, "reason": "smoke"},
])
res = run_autochain(
    client="eng", auth_ref="NPT-CLIENT-001", eng=lab_eng, scope_path=lab_scope,
    engagement_dir=lab_eng_dir, targets=[], workers=1, max_rounds=2, max_steps=5,
    skip_recon=True, llm=stub, log=lambda m: None,
)
check("unattested auto_lab autochain auto-ran NOTHING", res["ran"] == [])
check("unattested auto_lab autochain PARKED the FLOOR step", len(res["parked"]) == 1)
lab_gate = ApprovalGate(lab_eng_dir)
check("parked step is a real pending token", len(lab_gate.pending()) == 1)
lab_manifest = lab_eng_dir / "evidence" / "manifest.json"
check("no exploit evidence written (nothing executed)",
      (not lab_manifest.exists()) or len(__import__("json").loads(lab_manifest.read_text()).get("entries", [])) == 0)

print()
if _fails:
    print(f"FAILED: {_fails} check(s)")
    sys.exit(1)
print("all internal smoke checks passed")
