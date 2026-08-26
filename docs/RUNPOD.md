# RunPod runbook — Option A: LLM on RunPod, agents on your box

The split-brain setup: the **reasoning/triage LLM runs on a RunPod GPU**, the
**recon swarm runs on your local operator box** (16GB is fine — it never loads
model weights). This is the recommended topology; it keeps scan traffic
egressing from your authorized host while the GPU work lives in the cloud.

```
  operator box (16GB, on the wire)                RunPod (GPU)
  ┌───────────────────────────────┐               ┌────────────────────┐
  │ fullcheck run / swarm          │  recon egress │                    │
  │  → subfinder,httpx,naabu,      │──────────────▶│ (nothing scans     │
  │    katana,nuclei,gowitness...  │   from HERE   │  from here)        │
  │ evidence chain (local, hashed) │               │                    │
  │                                │  triage POST  │ vLLM               │
  │ fullcheck triage ──────────────┼──────────────▶│  OpenAI-compatible │
  │  (one batch of tool output)    │◀──────────────│  /v1/chat/...      │
  └───────────────────────────────┘  ranked JSON  └────────────────────┘
```

**The safety spine is unchanged by any of this.** Dispatcher (scope + ceiling +
rate), the two-gate exploit approval, and the evidence chain all run locally and
gate every action regardless of where the model lives. The LLM only ever sees
*tool-output text* to rank/dedupe/write up — it cannot invent findings and never
touches scope or credentials.

---

## Part 1 — the RunPod pod (the LLM)

### 1a. Pick a model and GPU (this is your real cost lever)

Triage ranks, dedupes, and writes up **real tool output** — it is not a frontier
reasoning task. A mid-size instruct model is plenty and costs a fraction of a
huge one. Do **not** serve the repo default `glm-4.6` on RunPod for this — it's a
very large model and massively overkill for triage.

| Model (as of writing) | Quant | Fits on | Notes |
|---|---|---|---|
| Qwen2.5-7B-Instruct / GLM-4-9B | AWQ/none | 1× 24GB (RTX 4090, A5000) | cheapest; fine for triage |
| Qwen2.5-14B-Instruct | AWQ | 1× 24GB | good balance |
| **Qwen2.5-32B-Instruct** | **AWQ** | **1× 48GB (L40S, A6000)** | **recommended** — best quality/cost for triage |
| Llama-3.3-70B-Instruct | AWQ | 2× 48GB or 1× 80GB (A100/H100) | diminishing returns for this job |

Rule of thumb: pick the smallest model that writes findings you'd sign your name
to. Start at 32B-AWQ on a single 48GB card; drop to 14B if cost matters.

### 1b. Launch vLLM (OpenAI-compatible server)

On the pod (or as the pod's container command). vLLM exposes an OpenAI-style
`/v1/chat/completions` endpoint, which is exactly what the OpenClaw client speaks.

```bash
# pick a served-model-name you'll reuse as OPENCLAW_MODEL, and a strong key
export SERVED_NAME="triage"
export VLLM_API_KEY="$(openssl rand -hex 24)"      # save this — the box needs it

vllm serve Qwen/Qwen2.5-32B-Instruct-AWQ \
    --served-model-name "$SERVED_NAME" \
    --api-key "$VLLM_API_KEY" \
    --quantization awq \
    --max-model-len 16384 \
    --gpu-memory-utilization 0.92 \
    --port 8000
```

Or with the official image (RunPod "Custom container" / template):

```
image:  vllm/vllm-openai:latest
port:   8000  (HTTP)
args:   --model Qwen/Qwen2.5-32B-Instruct-AWQ --served-model-name triage
        --api-key <VLLM_API_KEY> --quantization awq --max-model-len 16384
        --gpu-memory-utilization 0.92
```

If the pod OOMs on load: lower `--max-model-len` (e.g. 8192), lower
`--gpu-memory-utilization` (0.85), or step down a model size / use AWQ.

### 1c. Expose the endpoint — securely

Two sane options; **never** expose the raw port to the internet without the API
key, and prefer a private path:

- **RunPod HTTP proxy (simplest).** RunPod publishes each pod's HTTP port at
  `https://<POD_ID>-8000.proxy.runpod.net`. Your base URL becomes
  `https://<POD_ID>-8000.proxy.runpod.net/v1`. It's TLS-terminated by RunPod and
  still protected by `--api-key`. Good enough for a solo operator.
- **Tailscale (recommended for real engagements).** Install Tailscale on the pod,
  join your tailnet, and point the box at the pod's tailnet IP
  (`http://<pod-tailscale-ip>:8000/v1`). The endpoint is then only reachable
  inside your private mesh — no public exposure at all. Lock it further with
  tailnet ACLs so only your operator box can reach the pod.

Keep the `VLLM_API_KEY` regardless — defence in depth.

---

## Part 2 — the operator box (the agents, 16GB)

### 2a. Point FullCheck at the pod

Put these in a **git-ignored** env file (not the repo), e.g. `~/.fullcheck.env`,
and `source` it before a run:

```bash
# ~/.fullcheck.env   (chmod 600; never commit)
export OPENCLAW_BASE="https://<POD_ID>-8000.proxy.runpod.net/v1"   # or http://<tailscale-ip>:8000/v1
export OPENCLAW_MODEL="triage"          # must equal --served-model-name
export OPENCLAW_API_KEY="<VLLM_API_KEY>"
```

The client reads exactly these three vars (`src/fullcheck/llm/client.py`); its
120s timeout already covers a remote hop.

### 2b. Tune the swarm for 16GB

The workers spawn recon binaries, not the model. Most are light; the memory-heavy
ones are **gowitness** (headless Chromium, ~150–400MB each) and **nuclei** (big
template runs). So:

- In `scope.yaml`, set a realistic cap and start conservative:
  ```yaml
  rate_limits:
    requests_per_second_per_host: 5
    max_workers: 15        # start here on 16GB; push toward 20 only with headroom
  ```
  (`--workers` on the CLI is additionally hard-capped at 50 and by this value.)
- Add a swap safety-net so a Chromium/nuclei spike can't OOM-kill the run:
  ```bash
  sudo fallocate -l 8G /swapfile && sudo chmod 600 /swapfile
  sudo mkswap /swapfile && sudo swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
  ```
- Watch it on the first big run: `watch -n2 free -m`. If RAM is tight, the usual
  culprit is many gowitness tasks landing at once on a wide scope — lower
  `max_workers` or split screenshotting into its own lower-concurrency pass.

For the **home lab (2 hosts)** none of this matters — it's tiny.

### 2c. Optional: authenticated M365 + embeddings

- Graph scan needs `msal`: `pip install -e '.[m365]'` (see [M365.md](M365.md)).
- Semantic-CVE embeddings want a local GPU; with none, FullCheck **falls back to
  FTS5 keyword search** automatically — no scan capability lost. This is separate
  from the RunPod reasoning model.

---

## Part 3 — connectivity test (do this before a real run)

From the operator box, after `source ~/.fullcheck.env`:

```bash
# 1. raw endpoint reachability + auth (should return a JSON completion)
curl -sS "$OPENCLAW_BASE/chat/completions" \
  -H "Authorization: Bearer $OPENCLAW_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"$OPENCLAW_MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"reply with the single word READY\"}],\"max_tokens\":5}"

# 2. through FullCheck's own client (proves the tool will use it)
cd ~/fullcheck && source .venv/bin/activate
PYTHONPATH=src python -c "from fullcheck.llm.client import OpenClawClient; print(OpenClawClient().chat('You are a connectivity test.','Reply with the single word READY.'))"
```

Expect `READY` (or similar) from both. Common failures:
- **401/403** → key mismatch: `OPENCLAW_API_KEY` ≠ the pod's `--api-key`.
- **404 / "model not found"** → `OPENCLAW_MODEL` ≠ `--served-model-name`.
- **connection refused / timeout** → proxy URL wrong, pod still loading the model,
  or (Tailscale) box not on the tailnet / ACL blocking it.

---

## Part 4 — the run, end to end

```bash
source ~/.fullcheck.env
cd ~/fullcheck && source .venv/bin/activate

# EXTERNAL: recon locally (20-ish workers), triage on RunPod, report locally
fullcheck run   <client> --scope example.com --auth-ref REF     # or:
fullcheck swarm <client> --auth-ref REF --targets hosts.txt --workers 15
fullcheck triage <client>          # <-- the ONLY step that calls RunPod
fullcheck report <client>

# M365: recon/scan locally, deterministic analyze (no LLM), report
fullcheck m365 recon   <client> -d tenant.com --auth-ref REF
fullcheck m365 scan    <client> -d tenant.com --auth-ref REF     # needs .[m365]
fullcheck m365 analyze <client> -d tenant.com                    # deterministic, no LLM
fullcheck m365 report  <client> -d tenant.com --auth-ref REF

# INTERNAL (fcx): the box must be ON the client LAN — a cloud pod cannot do this
fcx swarm  <client> --auth-ref REF --range 10.0.0.0/24
```

Only `fullcheck triage` uses the model; everything else runs locally and writes
the hashed evidence chain tied to the auth reference. M365 `analyze` is
deliberately deterministic and does **not** use the LLM at all.

---

## Part 5 — security & hygiene

- **Never** put the endpoint on the public internet without the API key; prefer
  Tailscale for anything client-facing.
- Evidence, scope, and creds stay **on the operator box** — the pod only ever
  receives tool-output text at triage. Don't pipe raw client secrets to the model.
- Treat the pod as **ephemeral**: nothing of record lives there. Your chain of
  custody is local by design, which is exactly what you want.
- **Stop the pod when idle.** GPU time is the cost; triage is bursty. Spin up for
  a run, tear down after. (RunPod "spot"/on-demand is fine for this — a triage
  interruption just means re-running `fullcheck triage`, which is idempotent over
  the same evidence.)
- Rotate `VLLM_API_KEY` between engagements.

---

## Part 6 — why not run the workers on the pod too (Option B)?

Recap of the rejected alternative, so the choice is on record:

- **Internal work becomes impossible** — a cloud pod can't reach `192.168.x/10.x`
  client LANs; `fcx` must be a drop box on the wire.
- **External attribution gets messy** — recon then egresses from RunPod cloud IPs,
  which many programs flag/block and which muddies chain of custody.
- **Evidence would live on an ephemeral pod** — you'd have to persist and pull it.

Option B only earns its keep on a very large *external* scope where you've
declared a dedicated egress IP to the program. For everything else — and for all
internal work — keep the agents on your box. That's Option A.
