"""M365 probe base — an HTTP-based unit of work that still passes the spine.

The external/internal recon tools shell out to a binary (`tools/base.Tool`).
M365 recon is HTTP against Microsoft's shared endpoints, so it needs a different
executor — but it must reuse the *exact* safety spine: build an Action, run it
past `Dispatcher.check` (scope + ceiling + rate, keyed on the client domain),
and write the result into the shared Evidence chain (hashed, timestamped, tied to
the auth reference). That is what `M365Probe.run` does; subclasses only implement
`collect()`, which returns a JSON-able dict.

A probe is registered into `RECON_CATALOG` with `@register_probe` so the CLI and
the (future) swarm can enumerate what exists without importing each class.

Design rules for subclasses (agents adding probes, read this):
  * `name`   — stable kebab id, prefixed `m365-` (e.g. `m365-openid-config`).
  * `blast_radius` — PASSIVE for pure unauth metadata; PROBE for anything that
    tests account validity or otherwise looks like auth traffic to the tenant.
    NEVER put an authenticated-Graph or credential-sending action here — those
    are SCAN (graph.py) or FLOOR-gated (catalog.py) respectively.
  * `collect()` MUST NOT send a password or attempt a sign-in. If a check needs
    a secret, it belongs in graph.py (SCAN, app token) or catalog.py (gated).
  * `collect()` should be defensive: Microsoft endpoints change and rate-limit.
    Catch per-request errors and record them in the returned dict rather than
    raising, so one flaky endpoint doesn't sink the run. Include enough raw
    signal for analyze.py to reason over (status codes, key response fields).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

from ..action import Action, BlastRadius
from ..dispatcher import Dispatcher
from ..evidence import Evidence

# Microsoft shared endpoints. Requests egress here; scope is checked on the
# client domain (see package docstring).
LOGIN = "https://login.microsoftonline.com"
AUTODISCOVER = "https://autodiscover-s.outlook.com"
GRAPH = "https://graph.microsoft.com"

DEFAULT_UA = "FullCheck/0.2 (+authorized-assessment)"
DEFAULT_TIMEOUT = 20.0

# Politeness delay between per-item requests inside a single probe (e.g. one HTTP
# call per candidate user in enumeration). The Dispatcher rate limit is keyed on
# the client domain and only fires once per probe-level Action, so this is what
# actually keeps a multi-request probe from hammering Microsoft's endpoints.
INTER_REQUEST_DELAY = 0.4


def make_client(timeout: float = DEFAULT_TIMEOUT) -> httpx.Client:
    """A shared httpx client with sane defaults for Microsoft auth endpoints."""
    return httpx.Client(
        timeout=timeout,
        headers={"User-Agent": DEFAULT_UA, "Accept": "application/json"},
        follow_redirects=True,
    )


def polite_sleep(seconds: float = INTER_REQUEST_DELAY) -> None:
    if seconds > 0:
        time.sleep(seconds)


@dataclass
class M365Result:
    action: Action
    data: dict[str, Any]
    artifact_path: str


class M365Probe:
    """Base class for an unauthenticated M365 recon probe. See module docstring."""

    name: str = ""
    blast_radius: BlastRadius = BlastRadius.PASSIVE

    def collect(self, domain: str, params: dict, http: httpx.Client) -> dict[str, Any]:
        """Do the HTTP work and return a JSON-able dict. No sign-in, no password."""
        raise NotImplementedError

    def _action(self, domain: str, engagement: str, params: dict) -> Action:
        return Action(
            tool=self.name,
            target=domain,
            params={k: v for k, v in params.items() if k != "_http"},
            blast_radius=self.blast_radius,
            reason=params.get("_reason", ""),
            engagement=engagement,
        )

    def run(
        self,
        domain: str,
        engagement: str,
        dispatcher: Dispatcher,
        evidence: Evidence,
        params: dict | None = None,
        http: httpx.Client | None = None,
    ) -> M365Result:
        params = params or {}
        action = self._action(domain, engagement, params)
        dispatcher.check(action)  # scope + ceiling + rate, keyed on the domain
        own_client = http is None
        client = http or make_client()
        try:
            data = self.collect(domain, params, client)
        finally:
            if own_client:
                client.close()
        blob = json.dumps(data, indent=2, default=str).encode()
        artifact = evidence.record(
            action=action,
            stdout=blob,
            stderr=b"",
            exit_code=0,
            artifact_name=f"{self.name}_{domain.replace('/', '_').replace(':', '_')}",
        )
        return M365Result(action=action, data=data, artifact_path=str(artifact))


# ---- registry ---------------------------------------------------------------

RECON_CATALOG: dict[str, type[M365Probe]] = {}


def register_probe(cls: type[M365Probe]) -> type[M365Probe]:
    """Class decorator: add a probe to RECON_CATALOG keyed by its `name`."""
    if not cls.name:
        raise ValueError(f"{cls.__name__} must set a non-empty name to register")
    if cls.name in RECON_CATALOG:
        raise ValueError(f"duplicate probe name: {cls.name}")
    RECON_CATALOG[cls.name] = cls
    return cls


def load_probes() -> dict[str, type[M365Probe]]:
    """Import the recon module (populating RECON_CATALOG) and return it."""
    from . import recon as _  # noqa: F401 — import populates the registry

    return RECON_CATALOG


def run_recon(
    domain: str,
    engagement: str,
    dispatcher: Dispatcher,
    evidence: Evidence,
    probes: list[M365Probe] | None = None,
    params: dict | None = None,
    log: Callable[[str], None] = print,
) -> dict[str, Any]:
    """Run every registered PASSIVE/PROBE probe over one domain, spine-gated.

    A probe whose Action the Dispatcher denies (out of scope, over ceiling, rate
    limited) is skipped and recorded — never bypassed to keep busy.
    """
    from ..dispatcher import CeilingExceeded, RateLimited, ScopeViolation

    if probes is None:
        probes = [cls() for cls in load_probes().values()]
    params = params or {}
    summary: dict[str, Any] = {"ran": [], "skipped": [], "errors": []}
    http = make_client()
    try:
        for probe in probes:
            try:
                res = probe.run(
                    domain=domain,
                    engagement=engagement,
                    dispatcher=dispatcher,
                    evidence=evidence,
                    params=params,
                    http=http,
                )
                log(f"  [ok]   {probe.name} -> {domain} ({probe.blast_radius.value})")
                summary["ran"].append({"probe": probe.name, "domain": domain})
            except (ScopeViolation, CeilingExceeded, RateLimited) as e:
                log(f"  [DENY] {probe.name} -> {domain}: {e}")
                summary["skipped"].append({"probe": probe.name, "why": str(e)})
            except Exception as e:  # noqa: BLE001 — one probe must not sink the run
                log(f"  [err]  {probe.name} -> {domain}: {e}")
                summary["errors"].append({"probe": probe.name, "error": str(e)})
    finally:
        http.close()
    return summary
