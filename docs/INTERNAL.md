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

The gate class is defined by the catalog (`internal/catalog.py`), **not** by the
LLM and **not** by the autonomy dial — the same principle as lab-asset-suite's
schema-defined impact. `run_auto` re-checks FLOOR itself, so a routing bug can't
auto-fire a disruptive technique.

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
