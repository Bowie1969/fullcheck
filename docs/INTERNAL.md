# FullCheck-Internal (`fcx`) v0.3

The on-site / internal-network sibling of FullCheck. Same spine (Action,
Dispatcher, ApprovalGate, Evidence, the ≤50-worker swarm) — **imported, not
forked** — so the two tools can't drift apart on safety. What changes is what
the blast-radius tiers mean once you're on the wire, and a structural impact
class on every exploit technique.

## Runtime

Runs on an **x86 drop box (Parrot/Kali)** placed on the client LAN. Tools run
locally via subprocess, exactly like the external tool on ParrotOS. Provision
with:

```bash
sudo bash scripts/setup_dropbox.sh
```

(Your ARM64 laptop can't run the x86 pentest binaries directly, which is why the
box is the runtime — the laptop stays your operator console over SSH if you want
one.)

## The tier model on the wire

| Tier | Internal meaning | Runs how |
|------|------------------|----------|
| PASSIVE | listen-only (pcap, LLMNR/mDNS observe) | swarm, no gate |
| PROBE ("discovery") | ARP/ping sweep, port+service scan, SMB/LDAP/SNMP enum | swarm, no gate |
| SCAN | internal-web nuclei, authed vuln scan | swarm, ceiling-gated |
| EXPLOIT | reads, MITM, relay, spray, coercion, CVE exploit | catalog + autonomy |
| POST_EXPLOIT | secretsdump, lateral move, persistence | catalog, always gated |

## The autonomy dial and the hard floor

Set per engagement in `scope.yaml` as `autonomy:`:

- `gated` — every exploit-tier action stops for `fcx approve` (external-tool behaviour).
- `auto_low` — enum + CEILING techniques flagged `low_risk` auto-run; the rest gated.
- `aggressive` — every **CEILING** technique auto-runs within ceiling; only the
  **FLOOR** still gates. **This build ships configured for aggressive.**
- `auto_lab` — **fully autonomous, FLOOR included** (password spray, MITM, and
  all post-exploitation auto-run with no human token). Deliberately confined to
  the operator's **own lab** — see below.

For `gated`/`auto_low`/`aggressive`, the gate class is defined by the catalog
(`internal/catalog.py`), **not** by the LLM and **not** by the autonomy dial —
the same principle as lab-asset-suite's schema-defined impact. `run_auto`
re-checks FLOOR itself, so a routing bug can't auto-fire a disruptive technique.
`auto_lab` is the one mode that lowers that floor, and only on an attested lab.

### `auto_lab` — autonomous exploitation on your own lab (and nowhere else)

`auto_lab` removes the human confirm step for **every** technique, including the
FLOOR class and post-exploitation. Because that is exactly the capability that
would be catastrophic against a client, it is **structurally confined** — it only
lowers the floor when the engagement is attested as the operator's own lab. The
attestation (`autonomy.is_owned_lab`) requires **both**:

- `owned_lab: true` on the engagement, **and**
- an `auth_ref` that starts with `SELF-` (a self-authorization, not a client NPT).

If either is missing, `auto_lab` **fails safe to `gated`** — FLOOR is parked for
`fcx approve` exactly as normal. A client engagement therefore cannot auto-fire
an exploit even if someone typos `autonomy: auto_lab` into its block. Two more
controls remain in force:

- The **Dispatcher ceiling still applies.** To auto-run post-exploitation the
  engagement `ceiling` must actually be `post_exploit` (and `exploit` for the
  exploit tier). `auto_lab` never bypasses scope / ceiling / zone / rate.
- Every auto-fired FLOOR technique prints a loud `⚠ auto_lab AUTO-FIRING FLOOR`
  line and is written to the evidence chain like any other action.

A lab engagement therefore looks like:

```yaml
engagements:
  home-lab:
    auth_ref: SELF-LAB-20260826-001    # SELF-* → self-authorized
    owned_lab: true                    # explicit owned-lab attestation
    autonomy: auto_lab                 # fully autonomous (floor included)
    ceiling: post_exploit              # required for post-exploit to actually run
    interface: enp0s25
    scope: [192.168.88.0/24]
    out_of_scope: [192.168.88.10]
```

The gate class is still defined by the catalog; `auto_lab` doesn't reclassify
anything, it authorizes the auto path for FLOOR **on an attested lab only**.

### `fcx auto` — the LLM drives the whole chain

`fcx auto` is the autonomous driver: it runs recon, asks the LLM to **choose the
next exploits from the catalog**, executes them, feeds the results back, and
replans — a self-driving recon → exploit → post-exploit loop. The LLM is a
**proposer only**; three properties (enforced in code, not trusted to the model)
keep that as safe as `fcx attack`:

1. **Catalog-bound.** The planner may only name a `technique` that already exists
   in `internal/tools/exploit.py`. Unknown names, blank targets, and any
   model-set `blast_radius`/`gate_class` fields are dropped in
   `planner.validate_steps` before anything reaches the spine. The LLM never
   writes a shell command — `build_cmd` stays deterministic in the catalog.
2. **Impact is the catalog's, not the model's.** Each step's FLOOR/CEILING class
   and blast radius come from the technique class. The autonomy router
   (`autonomy.decide`) and `run_auto`'s FLOOR re-check are unchanged, so a step
   auto-fires only where the mode already allows.
3. **Enforcement is downstream and identical.** Every step passes the Dispatcher
   (scope + engagement/zone ceiling + rate) and writes the evidence chain.

Because of that, the mode is what decides how autonomous it actually is:

- **`auto_lab` on an attested owned lab** → FLOOR / post-exploit steps auto-fire
  with no per-step confirm (each prints the `⚠ auto_lab AUTO-FIRING FLOOR` line
  and is evidence-logged). This is the "runs the whole chain itself" behaviour.
- **any other engagement (incl. a client typo'd as `auto_lab`)** → the identical
  planner runs, but every FLOOR step is **PARKED for `fcx approve`**. The chain
  self-drives discovery and reversible reads and stops for a human on anything
  disruptive. The degradation is structural (`autonomy.decide` +
  `is_owned_lab`), not a flag in the driver.

It is bounded by `--max-rounds` (LLM plan/execute cycles), `--max-steps` (steps
per round), and a per-`(technique, target, params)` dedupe; a plan of `[]` ends
the chain early. The reasoning LLM is served through OpenClaw (`OPENCLAW_*` env);
if it is unreachable the chain **aborts** rather than falling back to running
anything on its own.

```bash
# Fully autonomous on your attested lab (one start-confirmation, then no gates):
fcx auto home-lab --auth-ref SELF-LAB-20260826-001 --range 192.168.88.0/24

# Same planner on a client engagement: FLOOR steps park for approval instead.
fcx auto acme-internal --auth-ref NPT-ACME-20260901-001 --range 10.10.0.0/24
fcx approve acme-internal --auth-ref NPT-ACME-20260901-001
fcx run     acme-internal --auth-ref NPT-ACME-20260901-001

# Replan from evidence you already collected (skip the recon swarm):
fcx auto home-lab --auth-ref SELF-LAB-20260826-001 --skip-recon -y
```

- **CEILING** (auto-runnable): reversible / non-disruptive — unauth file reads,
  info-disclosure, offline work.
- **FLOOR** (always human-confirmed, even in aggressive): password spray
  (lockout), Responder/ARP/relay MITM, coercion, host-crash-capable exploits
  (MS17-010), and **all** post-exploitation (secretsdump, wmiexec, persistence).

See exactly which is which:

```bash
fcx catalog
```

## Per-CIDR ceilings (segmentation safety)

`zone_ceilings` in an engagement caps fragile subnets below the engagement
ceiling — enforced by the Dispatcher for both the swarm and `fcx attack`:

```yaml
zone_ceilings:
  - cidr: 10.10.20.0/24   # OT/SCADA
    ceiling: probe        # discovery only, never scan/exploit
  - cidr: 10.10.0.10/32   # domain controller
    ceiling: scan
```

## Typical flow

```bash
cp scope.internal.example.yaml scope.yaml     # edit for the engagement
fcx new acme-internal --auth-ref NPT-ACME-20260901-001

# 1. discovery/enum — fans out, finds everything reachable (dispatcher-gated)
fcx swarm acme-internal --auth-ref NPT-ACME-20260901-001 --range 10.10.0.0/24

# 2. a reversible read — CEILING, auto-runs under aggressive
fcx attack acme-internal --technique web-file-read \
    --target 10.10.50.9 --auth-ref NPT-ACME-20260901-001 \
    --param 'url=http://10.10.50.9:3923/.cpr/%2Fetc%2Fpasswd'

# 3. a password spray — FLOOR, ALWAYS stops here even in aggressive
fcx attack acme-internal --technique password-spray \
    --target 10.10.0.0/24 --auth-ref NPT-ACME-20260901-001 \
    --param users=users.txt --param 'password=Autumn2026!'
#   -> parked for approval; you confirm the exact command:
fcx approve acme-internal --auth-ref NPT-ACME-20260901-001
fcx run     acme-internal --auth-ref NPT-ACME-20260901-001

# 4. report from the evidence chain
fcx report acme-internal
```

Every action — auto or gated — passes the Dispatcher (scope + engagement/zone
ceiling + rate) and writes the hashed evidence chain tied to the auth reference.

## Adding techniques

Subclass `InternalExploit` in `internal/tools/exploit.py`, set `name`,
`blast_radius`, and `gate_class` (default is FLOOR — default-deny), decorate with
`@register`, and give it a thin explicit `build_cmd`. That's the whole
extension point.
