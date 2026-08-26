# FullCheck v0.1

Single-operator external attack surface checkup tool.

## What it does

- Takes one authorized domain
- Enumerates external attack surface (subs, ports, tech, exposed panels, misconfigs, breached creds)
- Correlates findings against a local CVE + Nuclei-template intelligence cache
- LLM triages, dedupes, and drafts finding writeups via OpenClaw
- Auto-collects evidence tied to the authorization letter reference
- Emits a clean markdown report

## Scope

Recon and scanning are external / passive-to-scan. Exploitation is supported
**only** behind two independent gates (see "Exploitation" below) and only for
engagements whose `scope.yaml` ceiling is explicitly `exploit`. Internal work
belongs to `FullCheck-Internal` (v0.3).

## Legal / ethical requirement

Every engagement MUST have a signed authorization letter before any target is added
to `scope.yaml`. The dispatcher enforces scope at the tool-call level; there is
no "just this once" override. Authorization reference is captured in every
evidence artifact.

## Install (ParrotOS)

```bash
bash scripts/setup_parrot.sh
pip install -e .
```

## Usage

```bash
fullcheck new <client-slug>                                    # create engagement folder
fullcheck run <client-slug> --scope example.com --auth-ref REF # execute recon (serial)
fullcheck triage <client-slug>                                 # LLM-rank findings
fullcheck report <client-slug>                                 # emit markdown report
```

### Microsoft 365 / Entra ID (`fullcheck m365`)

External cloud-tenant assessment on the same spine. The target is the client's
**tenant domain** (must be in `scope.yaml`); recon egresses only to Microsoft's
shared endpoints, never to client infrastructure. Tiers: unauthenticated recon
(PASSIVE) + account-validity enum (PROBE, no password sent), authenticated
read-only Graph reads (SCAN, needs an app registration), and a FLOOR-only
active-technique catalog behind the existing approval gate.

```bash
fullcheck m365 recon   <client> -d tenant.com --auth-ref REF [--users cand.txt]
fullcheck m365 scan    <client> -d tenant.com --auth-ref REF   # authenticated Graph (needs .[m365])
fullcheck m365 analyze <client> -d tenant.com                  # deterministic findings, no LLM
fullcheck m365 report  <client> -d tenant.com --auth-ref REF   # -> m365_report.md
fullcheck m365 catalog                                         # FLOOR-gated active techniques
```

See [docs/M365.md](docs/M365.md) for the app-registration scopes, credential
options, and the full walkthrough.

### Parallel recon (the "swarm")

`swarm` fans the recon/scan pipeline out across many targets concurrently. It is
bounded by `--workers` (hard cap 50) **and** the per-host rate limit in
`scope.yaml`, so N workers spread across many hosts rather than hammering one.
Every task still passes the same dispatcher (scope + ceiling + rate) and writes
to the same evidence chain. Exploitation never runs here.

```bash
fullcheck swarm <client-slug> --auth-ref REF --targets hosts.txt --workers 50
```

To scale out — recon workers on your operator box, the triage LLM on a RunPod
GPU — see the [RunPod runbook](docs/RUNPOD.md).

### Exploitation (two gates, one human confirmation per exploit)

Exploitation is deliberately serial and human-gated. A worker or the operator
*proposes* an exploit; nothing runs until a human confirms that exact command.

1. **Gate 1 — engagement ceiling.** The dispatcher rejects any exploit unless
   the engagement's `ceiling` in `scope.yaml` is `exploit`. A scan-ceiling job
   can never exploit, full stop.
2. **Gate 2 — per-exploit human confirmation.** Each proposed exploit is parked
   with a single-use, time-limited token. Only an explicit human `confirm`
   releases it; the token is burned on execution so it can never run twice.
   Neither the LLM nor a worker can mint or self-approve a token.

```bash
# propose (validates scope+ceiling; does NOT run). Everything after -- is the exact argv.
fullcheck exploit-propose <client-slug> --target 10.0.0.5 --id CVE-2023-37474 \
    --auth-ref REF -- curl -sik "http://10.0.0.5:3923/.cpr/%2Fetc%2Fpasswd"

fullcheck exploit-queue <client-slug>                 # list what's pending
fullcheck approve <client-slug> --auth-ref REF        # confirm/deny EACH one interactively
fullcheck exploit-run <client-slug> --auth-ref REF    # run only confirmed tokens; evidence-logged
```

Every transition (proposed → confirmed/denied → consumed/expired) is written to
`engagements/<client>/exploit_audit.jsonl` for chain of custody.

## Optional GTX acceleration

The GTX is not used for scanning or OpenClaw reasoning. It can accelerate the
optional local semantic CVE index. On ParrotOS, after the NVIDIA driver is
working, install the optional dependency and build the index:

```bash
pip install -e '.[embed]'
fullcheck intel-status
fullcheck update-intel --years 2024,2025,2026 --embeddings
# or, after a normal CVE refresh:
fullcheck build-embeddings
```

If CUDA is unavailable or the GTX has insufficient VRAM, FullCheck safely uses
CPU embeddings or its built-in FTS5 keyword search. No scan capability is lost.

## Layout

```
fullcheck/
  scope.yaml                # allowlist per engagement (git-ignored per-client)
  engagements/<client>/
    auth.txt                # authorization letter reference
    evidence/manifest.json  # chain of custody
    raw/                    # per-tool JSON output
    findings.json           # triaged, ranked
    report.md               # final deliverable
    exploit_queue.json      # live approval state (per engagement)
    exploit_audit.jsonl     # append-only approval chain of custody
  src/fullcheck/
    action.py               # typed Action dataclass (blast_radius etc.)
    dispatcher.py           # scope + ceiling + rate (thread-safe)
    approval.py             # per-exploit human-in-the-loop token gate
    orchestrator.py         # parallel recon/scan worker pool (the swarm)
    evidence.py             # hash + timestamp + manifest (thread-safe)
    cli.py                  # Typer CLI
    tools/                  # tool wrappers (subprocess -> JSON)
      recon.py              #   passive/probe/scan tiers
      exploit.py            #   exploit tier — gated by approval.py
    llm/                    # OpenClaw client + triage prompt
    intel/                  # CVE + Nuclei-template SQLite cache
    report/                 # markdown template + generator
```

## Roadmap

- v0.1: external checkup (this) - 8 hours
- v0.1+: parallel recon swarm + per-exploit HITL approval gate **(landed)**
- v0.2: M365/Entra module + HITL blast-radius gate **(landed)** — `fullcheck
  m365` subcommand, reuses this spine. Unauth tenant recon (PASSIVE/PROBE),
  authenticated read-only Graph scan (SCAN), deterministic findings, and a
  FLOOR-only active-technique catalog behind the existing approval gate. See
  [docs/M365.md](docs/M365.md).
- v0.3: FullCheck-Internal (on-site sibling tool) **(landed)** — `fcx` CLI,
  reuses this spine (dispatcher/approval/evidence/swarm). Internal blast-radius
  remap + structural FLOOR/CEILING technique catalog + per-CIDR `zone_ceilings`.
  Runs on an x86 drop box. See [docs/INTERNAL.md](docs/INTERNAL.md).
- v0.4: multi-worker dispatcher, queue
- v0.5: richer exploit-tool catalog + Sliver integration (still HITL-gated)
- v1.0: multi-client dashboard, continuous monitoring, invoicing
