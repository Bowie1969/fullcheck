"""Authenticated Microsoft Graph client + the SCAN-tier check harness.

This is the SCAN tier of the M365 module: authenticated, read-only Graph GETs
that pull the tenant's security posture (Conditional Access, MFA registration,
privileged roles, ...). Every check is still an Action that passes
`Dispatcher.check` at SCAN tier keyed on the client domain, and every response is
written to the shared Evidence chain — an app token is not a bypass of the spine.

Auth: `msal` is an OPTIONAL dependency (`pip install -e '.[m365]'`). It is imported
lazily so the rest of FullCheck works without it. Credentials are NEVER read from
scope.yaml (that file is about authorization, not secrets). They come from, in
order of precedence:
  1. environment: M365_TENANT_ID, M365_CLIENT_ID, M365_CLIENT_SECRET
  2. a git-ignored per-engagement file: engagements/<client>/m365_app.json
     {"tenant_id": "...", "client_id": "...", "client_secret": "..."}
Omit the secret to use the interactive device-code flow (delegated read scopes).

The check registry (`GRAPH_CHECKS`) is filled by graph_checks.py — each entry is
a read-only endpoint plus the delegated/app scope it needs. run_scan() iterates
them, tolerating per-endpoint failures (a missing scope shows up as one skipped
check, not a dead run).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import httpx

from ..action import Action, BlastRadius
from ..dispatcher import Dispatcher
from ..evidence import Evidence
from .base import GRAPH, LOGIN, make_client

GRAPH_BASE = f"{GRAPH}/v1.0"
DEFAULT_SCOPES = ["https://graph.microsoft.com/.default"]


class GraphError(RuntimeError):
    pass


@dataclass
class GraphCheck:
    """One read-only Graph endpoint to pull during a scan.

    key:      short id, used in the evidence artifact name (e.g. `ca-policies`).
    path:     Graph path under /v1.0 (e.g. `/identity/conditionalAccessPolicies`).
    scope:    human note of the delegated/app permission it needs (for the report).
    paginate: follow @odata.nextLink to pull all pages (default True).
    """

    key: str
    path: str
    scope: str = ""
    paginate: bool = True


# Filled by graph_checks.py via register_check().
GRAPH_CHECKS: list[GraphCheck] = []


def register_check(check: GraphCheck) -> GraphCheck:
    GRAPH_CHECKS.append(check)
    return check


def load_checks() -> list[GraphCheck]:
    from . import graph_checks as _  # noqa: F401 — import populates GRAPH_CHECKS

    return GRAPH_CHECKS


# ---- credentials ------------------------------------------------------------


@dataclass
class GraphCreds:
    tenant_id: str
    client_id: str
    client_secret: str = ""  # empty => device-code (delegated) flow

    @property
    def use_device_code(self) -> bool:
        return not self.client_secret


def load_creds(engagement_dir: Path) -> GraphCreds:
    """Resolve app-registration creds from env, then the git-ignored eng file."""
    import os

    tid = os.environ.get("M365_TENANT_ID", "")
    cid = os.environ.get("M365_CLIENT_ID", "")
    sec = os.environ.get("M365_CLIENT_SECRET", "")
    app_file = Path(engagement_dir) / "m365_app.json"
    if (not tid or not cid) and app_file.exists():
        blob = json.loads(app_file.read_text())
        tid = tid or str(blob.get("tenant_id", ""))
        cid = cid or str(blob.get("client_id", ""))
        sec = sec or str(blob.get("client_secret", ""))
    if not tid or not cid:
        raise GraphError(
            "no Graph app registration found. Set M365_TENANT_ID + M365_CLIENT_ID "
            "(+ optional M365_CLIENT_SECRET) or write engagements/<client>/m365_app.json"
        )
    return GraphCreds(tenant_id=tid, client_id=cid, client_secret=sec)


# ---- client -----------------------------------------------------------------


class GraphClient:
    """Thin authenticated Graph GET client. Read-only by construction."""

    def __init__(self, creds: GraphCreds, http: httpx.Client | None = None,
                 log: Callable[[str], None] = print):
        self.creds = creds
        self.http = http or make_client(timeout=60.0)
        self.log = log
        self._token: str | None = None

    def _acquire_token(self) -> str:
        try:
            import msal  # lazy: optional dependency
        except ImportError as e:  # pragma: no cover
            raise GraphError(
                "msal not installed — run: pip install -e '.[m365]'"
            ) from e
        authority = f"{LOGIN}/{self.creds.tenant_id}"
        if self.creds.use_device_code:
            app = msal.PublicClientApplication(self.creds.client_id, authority=authority)
            flow = app.initiate_device_flow(scopes=["https://graph.microsoft.com/.default"])
            if "user_code" not in flow:
                raise GraphError(f"device flow init failed: {flow.get('error_description')}")
            self.log(flow["message"])  # instructs the operator to visit the URL + code
            result = app.acquire_token_by_device_flow(flow)
        else:
            app = msal.ConfidentialClientApplication(
                self.creds.client_id, authority=authority,
                client_credential=self.creds.client_secret,
            )
            result = app.acquire_token_for_client(scopes=DEFAULT_SCOPES)
        if "access_token" not in result:
            raise GraphError(
                f"token acquisition failed: {result.get('error')}: "
                f"{result.get('error_description')}"
            )
        return result["access_token"]

    def token(self) -> str:
        if self._token is None:
            self._token = self._acquire_token()
        return self._token

    def get(self, path: str, paginate: bool = True) -> dict[str, Any]:
        """GET a Graph path (relative to /v1.0). Follows nextLink if paginate."""
        url = path if path.startswith("http") else f"{GRAPH_BASE}{path}"
        headers = {"Authorization": f"Bearer {self.token()}"}
        values: list[Any] = []
        first: dict[str, Any] = {}
        pages = 0
        while url:
            r = self.http.get(url, headers=headers)
            if r.status_code == 403:
                raise GraphError(f"403 (missing scope?) for {path}")
            r.raise_for_status()
            body = r.json()
            if not first:
                first = body
            if "value" in body:
                values.extend(body["value"])
                url = body.get("@odata.nextLink") if paginate else None
            else:
                return body  # single object response
            pages += 1
            if pages > 200:  # safety backstop against a pathological nextLink loop
                break
        return {"value": values, "@odata.count": len(values)}


# ---- scan harness -----------------------------------------------------------


def run_scan(
    domain: str,
    engagement: str,
    engagement_dir: Path,
    dispatcher: Dispatcher,
    evidence: Evidence,
    creds: GraphCreds,
    checks: list[GraphCheck] | None = None,
    log: Callable[[str], None] = print,
) -> dict[str, Any]:
    """Run each SCAN-tier Graph check, spine-gated and evidence-logged.

    Each check builds a SCAN Action on the client domain; the Dispatcher rejects
    the whole scan up front if the engagement ceiling is below `scan`. A 403 /
    missing-scope on one endpoint is recorded and the scan continues.
    """
    from ..dispatcher import CeilingExceeded, RateLimited, ScopeViolation

    checks = checks if checks is not None else load_checks()
    client = GraphClient(creds, http=make_client(timeout=60.0), log=log)
    summary: dict[str, Any] = {"ran": [], "skipped": [], "errors": [], "tenant": domain}
    try:
        for chk in checks:
            action = Action(
                tool=f"graph-{chk.key}",
                target=domain,
                params={"path": chk.path, "scope": chk.scope},
                blast_radius=BlastRadius.SCAN,
                reason="authenticated Graph read (SCAN)",
                engagement=engagement,
            )
            try:
                dispatcher.check(action)  # ceiling must be >= scan for this domain
            except (ScopeViolation, CeilingExceeded, RateLimited) as e:
                log(f"  [DENY] graph-{chk.key}: {e}")
                summary["skipped"].append({"check": chk.key, "why": str(e)})
                continue
            try:
                data = client.get(chk.path, paginate=chk.paginate)
            except (GraphError, httpx.HTTPError) as e:
                log(f"  [skip] graph-{chk.key}: {e}")
                summary["skipped"].append({"check": chk.key, "why": str(e)})
                continue
            blob = json.dumps(data, indent=2, default=str).encode()
            evidence.record(
                action=action, stdout=blob, stderr=b"", exit_code=0,
                artifact_name=f"graph-{chk.key}_{domain}",
            )
            n = len(data.get("value", [])) if isinstance(data, dict) else 0
            log(f"  [ok]   graph-{chk.key} ({n} records)")
            summary["ran"].append({"check": chk.key, "records": n})
    finally:
        client.http.close()
    return summary
