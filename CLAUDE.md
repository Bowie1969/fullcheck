# FullCheck — project context for Claude Code

This file is read automatically by Claude Code in this repo, on any machine.
It exists because the `~/.claude` auto-memory is machine-local and does not sync
to the Parrot box. Keep it updated when the architecture or rules change.

## What this is

Two sibling offensive-security tools sharing one safety spine, for a solo
operator (Will / Full Check Security) doing **authorized** bug-bounty + pentest
work. NOT an autonomous "50-agent 24/7 fleet against production" — that idea was
deliberately talked down (60–80% bounty dupe rate, platform-ban risk, illegality
against untargeted hosts). This is operator-driven and scope-gated.

- **`fullcheck`** — external attack-surface tool. Pipeline: `new` → `run`/`swarm`
  (recon) → `triage` (LLM) → `report` (markdown).
- **`fcx`** (`src/fullcheck/internal/`) — on-site / internal sibling. Runs on an
  x86 drop box. Reuses the spine; adds an internal technique catalog with a
  structural FLOOR/CEILING and per-CIDR `zone_ceilings`. See `docs/INTERNAL.md`.
  The `auto_lab` autonomy mode is the ONE carve-out that auto-runs FLOOR /
  post-exploit with no human confirm — structurally confined to an attested
  owned lab (`owned_lab: true` + `SELF-*` auth_ref), else it fails safe to
  `gated`. It never applies to a client engagement.

## The safety spine — DO NOT weaken these

Every tool call — external or internal — passes the same gates. This is the
legal and ethical core of the project; treat it as load-bearing.

1. **`dispatcher.py`** — `Dispatcher.check(Action)` enforces, per engagement:
   scope allowlist (`scope.yaml`), blast-radius **ceiling** (tightened per-CIDR
   by `zone_ceilings`), and per-host rate limit. Thread-safe. There is no
   "just this once" override.
2. **`action.py`** — `BlastRadius` ladder: `passive < probe < scan < exploit <
   post_exploit`. Recon/scan is auto. Exploit is not.
3. **`approval.py`** — exploitation needs TWO independent gates: (a) the
   engagement `ceiling` in `scope.yaml` must be `exploit`; (b) a per-exploit,
   single-use, time-limited human `confirm` token. **Neither the LLM nor a
   worker may mint, self-approve, or bypass a token.** Tokens burn on use.
4. **`evidence.py`** — every artifact hashed (sha256) + timestamped + tied to
   `auth_ref`, in `evidence/manifest.json`. Exploit transitions append to
   `exploit_audit.jsonl`. Thread-safe.

**Absolute rule:** a target enters `scope.yaml` only with a signed written
authorization on file first — this holds even for a client the operator knows
personally or is related to. A personal relationship is not a defence under the
AU Cybercrime Act.

## Layout

- `orchestrator.py` — the swarm: parallel recon/scan pool, bounded by `--workers`
  (hard cap 50) AND per-host rate limit. Exploitation NEVER runs here (serial +
  gated only).
- `tools/recon.py` — subfinder, dnsx, httpx, naabu, katana, nuclei, gowitness,
  trufflehog, dnstwist. Graceful skip if a binary is absent.
- `tools/exploit.py` — exploit tier; only runs behind `approval.py`.
- `intel/cve_cache.py` — SQLite + FTS5. Ingests via the **NVD 2.0 REST API**
  (legacy 1.1 feeds are retired → 403). Set `NVD_API_KEY` env or ingestion is
  slow (5 req/30s).
- `intel/embeddings.py` — optional semantic CVE search (bge-small, cosine). The
  ONLY GPU role (any GTX ≥6GB, CUDA auto-detected). Falls back to FTS5 if
  absent/no-GPU/error. A GTX CANNOT serve the reasoning LLM — that stays on
  OpenClaw/RunPod.
- `llm/` — OpenClaw client (OpenAI-compatible; env `OPENCLAW_BASE/MODEL/API_KEY`).
  Triage prompt forbids inventing findings — it may only rank/dedupe/describe
  real tool output.

## Environment

- Reasoning LLM is served through **OpenClaw** (Will's local gateway), not in
  this repo. Set the `OPENCLAW_*` env vars.
- Will's primary laptop is **Windows-on-ARM64** — cannot run x86 recon binaries
  or vLLM. The **ParrotOS laptop (x86)** is where recon/`fcx` actually run.
- `scope.yaml` and `engagements/` are git-ignored (per-client, sensitive).

## Testing

`python scripts/smoke_test.py` (core: scope/ceiling/rate/evidence/report +
exploit approval gate) and `python scripts/test_embeddings.py` (cosine + FTS
fallback). Run them after touching the dispatcher, approval gate, or evidence
code — those are the safety-critical paths. Recon binaries only exist on Parrot;
their wrappers skip gracefully elsewhere so the logic still tests on any box.

## Roadmap state

v0.1 external + swarm + HITL exploit gate: landed. `fcx` internal: landed.
Next requested: **v0.2 M365/Entra module** (+ its own scan-tier gating). Not
started. Later: v0.4 richer queue, v0.5 Sliver integration (still HITL-gated),
v1.0 dashboard + continuous monitoring.
