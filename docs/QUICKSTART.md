# FullCheck v0.1 — Operator Quickstart

## 0. Before anything: authorization

Do not add a target to `scope.yaml` until a **signed authorization letter**
exists. The dispatcher enforces scope in code, but the letter is what makes the
activity legal. File it at `engagements/<client>/auth.txt` (reference) with the
real signed copy stored securely.

Even for a client you know personally or are related to: their owning the
business is **not** a substitute for written authorization. Email scope + dates
+ your contact, get a "yes, authorized" reply in writing, reference it as the
`auth_ref`.

## 1. Setup (on the ParrotOS laptop, once)

```bash
git clone <however-you-sync>/fullcheck   # or rsync from OneDrive
cd fullcheck
bash scripts/setup_parrot.sh
export PATH="$PATH:$HOME/go/bin"
source .venv/bin/activate
```

Point it at OpenClaw (defaults assume a local OpenAI-compatible endpoint):

```bash
export OPENCLAW_BASE="http://127.0.0.1:8787/v1"   # your gateway
export OPENCLAW_MODEL="glm-4.6"                    # or whatever you route
export OPENCLAW_API_KEY="sk-local"
```

## 2. Build the CVE cache (once, then weekly)

```bash
fullcheck update-intel --years 2023,2024,2025,2026
```

Pulls CVEs from the **NVD 2.0 REST API** into `intel/cache.db` (FTS5 search; no
GPU needed). The legacy JSON feeds are retired — this uses the current API.

**Get a free NVD API key first.** The API is slow and rate-limited to 5
requests / 30s without a key (a full year can take ~8+ minutes). A free key
(https://nvd.nist.gov/developers/request-an-api-key) raises it to 50 / 30s.
Export it before running:

```bash
export NVD_API_KEY="your-key-here"
```

### Optional: enable the GTX for semantic CVE matching

After `nvidia-smi` works on ParrotOS, install the optional embedding package:

```bash
pip install -e '.[embed]'
fullcheck intel-status
fullcheck build-embeddings
```

FullCheck selects CUDA automatically when PyTorch can see the GTX. If it cannot,
the system falls back to CPU embeddings; if the package is absent it falls back
to FTS5 keyword search. A CVE refresh invalidates the vectors intentionally, so
rerun `fullcheck build-embeddings` (or add `--embeddings` to `update-intel`).

## 3. Per engagement

```bash
# a) scaffold
fullcheck new example-q1 --auth-ref EXAMPLE-2026-Q1

# b) add the engagement block to scope.yaml (copy from scope.yaml.example):
#    - auth_ref, authorized_by, starts/ends, ceiling: scan, scope list
#    Anything not listed here is rejected at the dispatcher.

# c) run recon (every tool call is scope- + ceiling- + rate-gated)
fullcheck run example-q1 --scope example.com --auth-ref EXAMPLE-2026-Q1

# d) LLM triage (correlates CVEs, ranks, dedupes, drafts writeups)
fullcheck triage example-q1

# e) render the report
fullcheck report example-q1
```

Deliverable lands at `engagements/example-q1/report.md`.
Evidence chain at `engagements/example-q1/evidence/manifest.json`.

## 4. What the dispatcher blocks

- Any target not in that engagement's `scope` list -> `ScopeViolation`
- Anything in `out_of_scope` -> `ScopeViolation`
- Any tool whose blast radius exceeds the engagement `ceiling` -> `CeilingExceeded`
- Bursts above the per-host rate limit -> `RateLimited`

These are not warnings. The tool refuses to send the packet.

## 5. Review before you send

The LLM produces **candidate** findings from real tool output — it cannot
invent findings, but it can misjudge severity. Read every finding, verify the
evidence artifact, and adjust before the report goes to a client. You sign it,
not the model.

## Blast-radius ladder (for later versions)

| Level | v0.1 behavior |
|-------|---------------|
| passive | auto-run (subfinder, dnsx, trufflehog, dnstwist) |
| probe | auto-run (httpx, naabu, katana, gowitness) |
| scan | auto-run **only if** engagement ceiling >= scan (nuclei) |
| exploit | not implemented — v0.5, human-approved only |
| post_exploit | not implemented — v0.5, per-action approval |
