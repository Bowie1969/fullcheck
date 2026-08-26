"""FullCheck v0.2 — Microsoft 365 / Entra ID module.

External-facing cloud-tenant assessment, wired into the same safety spine as the
rest of FullCheck (Action, Dispatcher, Evidence, ApprovalGate). It lives under
the `fullcheck m365 ...` subcommand group.

Scope semantics (important):
  M365 recon talks to Microsoft's *shared* endpoints — login.microsoftonline.com,
  autodiscover-s.outlook.com, graph.microsoft.com — never to infrastructure the
  client controls. The thing being ASSESSED, and therefore the Dispatcher
  `target`, is the client's tenant, identified by one of its verified domains
  (e.g. `contoso.com`). So scope.yaml must list the client domain(s); the
  Dispatcher scope/ceiling/rate check runs against that domain exactly as it does
  for any other target. Requests egress to Microsoft; authorization is checked
  against the tenant we were hired to look at.

Tier model for the cloud:
  * PASSIVE — unauthenticated tenant metadata (OpenID config, user-realm /
    federation, tenant domain list). No auth attempt, no client-controlled infra.
  * PROBE   — account validity enumeration (GetCredentialType). No password is
    ever sent, so no lockout — but it is logged/alertable, so it is rate-limited.
  * SCAN    — authenticated Microsoft Graph *reads* (CA policies, MFA
    registration, privileged roles, ...). Requires an app registration and is
    gated by the engagement ceiling exactly like every other SCAN-tier action.

  EXPLOIT — password spray / MFA-fatigue / illicit-consent against a live tenant
  carries real lockout + alerting + user-impact risk. This module NEVER sends a
  credential or an auth attempt on the auto path. Such actions are FLOOR-class in
  `catalog.py`: they route through the existing human ApprovalGate (ceiling must
  be `exploit`, plus a per-action confirm token) — see docs/M365.md.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.2.0"
