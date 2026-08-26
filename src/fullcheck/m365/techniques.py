"""M365 active-technique catalog entries — all FLOOR-gated (see catalog.py).

These are the tenant-attacking techniques (they send credentials, auth attempts,
or consent requests at a live tenant). Every one is FLOOR: it runs ONLY behind
`ceiling: exploit` in scope.yaml AND a per-action human confirm token. Several
ship as `stub = True` — the gate and the intent are wired, but no live tool
invocation is, so nothing can fire until an operator deliberately implements
`_build` against an authorized tool. That is the point: ship the safety gate
before the weapon.

Target is always the client tenant domain; the Dispatcher enforces `exploit`
ceiling on it, and `fullcheck m365 attack -> approve -> run` is the existing
tested exploit path.
"""

from __future__ import annotations

from typing import Sequence

from ..action import BlastRadius
from .catalog import M365Technique, register


@register
class PasswordSpray(M365Technique):
    """One password across many tenant accounts via the login endpoint.
    RISK: Entra Smart Lockout, sign-in-log alerts, possible account lockout."""

    name = "m365-password-spray"
    blast_radius = BlastRadius.EXPLOIT
    stub = True
    risk = "account lockout + SOC sign-in alerts on a live tenant"


@register
class MfaFatigue(M365Technique):
    """Repeated MFA push prompts to pressure a user into approving (push-bombing).
    RISK: direct end-user harassment; highly visible; account takeover if approved."""

    name = "m365-mfa-fatigue"
    blast_radius = BlastRadius.EXPLOIT
    stub = True
    risk = "harasses a real user with push prompts; account takeover on approval"


@register
class IllicitConsent(M365Technique):
    """Send an OAuth app-consent phishing link to obtain delegated Graph tokens.
    RISK: social-engineers a real user; grants persistent tenant access if consented."""

    name = "m365-illicit-consent"
    blast_radius = BlastRadius.EXPLOIT
    stub = True
    risk = "phishes a real user; persistent OAuth grant into the tenant on consent"


@register
class TokenReplay(M365Technique):
    """Replay a stolen/primary-refresh token to obtain access tokens (post-compromise).
    RISK: post-exploitation; acts as a compromised identity inside the tenant."""

    name = "m365-token-replay"
    blast_radius = BlastRadius.POST_EXPLOIT
    stub = True
    risk = "post-compromise identity impersonation inside the tenant"
