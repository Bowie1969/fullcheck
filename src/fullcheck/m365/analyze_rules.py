"""Deterministic findings rules over M365 recon + Graph artifacts.

Each @rule(fn) reads the parsed AnalyzeContext and returns zero or more findings
in the report schema (see analyze.py). Rules must be conservative: only assert
what the artifact actually shows, and cite the artifact in `evidence_artifact`.
Add coverage by appending a small pure function decorated with @rule.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .analyze import AnalyzeContext, Finding, rule


def _f(title: str, severity: str, artifact: str, summary: str, remediation: str,
       confidence: str = "medium", **extra: Any) -> Finding:
    out: Finding = {
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "evidence_artifact": artifact,
        "summary": summary,
        "remediation": remediation,
        "cve": [],
    }
    out.update(extra)
    return out


# ---- unauth recon rules -----------------------------------------------------


@rule
def federated_domain_adfs(ctx: AnalyzeContext) -> list[Finding]:
    out: list[Finding] = []
    for a in ctx.recon("userrealm"):
        p = a.payload
        if p.get("is_federated") and p.get("auth_url"):
            out.append(_f(
                title="Tenant uses federated (ADFS) authentication",
                severity="info",
                confidence="high",
                artifact=a.rel,
                summary=(
                    f"The domain federates authentication to an on-premises "
                    f"identity provider (brand: {p.get('federation_brand')!r}, "
                    f"AuthURL: {p.get('auth_url')}). A federation server such as "
                    f"ADFS is internet-facing and expands the tenant's external "
                    f"attack surface (password spray, Golden SAML, CVE exposure)."
                ),
                remediation=(
                    "Confirm the federation server is patched and monitored, or "
                    "migrate to Entra managed authentication (PHS/PTA with "
                    "seamless SSO) to shrink the external footprint."
                ),
            ))
    return out


@rule
def enumerated_valid_users(ctx: AnalyzeContext) -> list[Finding]:
    out: list[Finding] = []
    for a in ctx.recon("user-enum"):
        valid = a.payload.get("valid") or []
        if valid:
            out.append(_f(
                title=f"Valid accounts enumerable without authentication ({len(valid)})",
                severity="low",
                confidence="high",
                artifact=a.rel,
                summary=(
                    f"{len(valid)} candidate account(s) were confirmed to exist via "
                    f"the unauthenticated GetCredentialType endpoint (no password "
                    f"required). Account validity oracles let an attacker build a "
                    f"precise target list for password spraying and phishing."
                ),
                remediation=(
                    "Account existence via GetCredentialType cannot be fully "
                    "disabled, but the downstream risk is mitigated by enforcing "
                    "MFA for all users, blocking legacy authentication, and "
                    "enabling Entra Smart Lockout / sign-in risk policies."
                ),
            ))
    return out


# ---- authenticated Graph rules ----------------------------------------------


def _ca_policies(ctx: AnalyzeContext) -> tuple[list[dict], str] | None:
    a = ctx.graph("ca-policies")
    if a is None:
        return None
    return (a.payload.get("value", []) if isinstance(a.payload, dict) else []), a.rel


@rule
def no_mfa_conditional_access(ctx: AnalyzeContext) -> list[Finding]:
    got = _ca_policies(ctx)
    if got is None:
        return []
    policies, art = got
    enabled = [p for p in policies if p.get("state") == "enabled"]
    def requires_mfa(p: dict) -> bool:
        controls = (p.get("grantControls") or {}).get("builtInControls") or []
        return "mfa" in controls
    if not any(requires_mfa(p) for p in enabled):
        return [_f(
            title="No enabled Conditional Access policy requires MFA",
            severity="high",
            confidence="high",
            artifact=art,
            summary=(
                f"Of {len(policies)} Conditional Access policies ({len(enabled)} "
                f"enabled), none enforce multi-factor authentication via a grant "
                f"control. Accounts are protected by password alone, leaving the "
                f"tenant highly exposed to password spray and credential stuffing."
            ),
            remediation=(
                "Create/enable a Conditional Access policy requiring MFA for all "
                "users and all cloud apps (or enable Security Defaults on smaller "
                "tenants). Exclude only break-glass accounts."
            ),
        )]
    return []


@rule
def report_only_mfa_policy(ctx: AnalyzeContext) -> list[Finding]:
    got = _ca_policies(ctx)
    if got is None:
        return []
    policies, art = got
    out: list[Finding] = []
    for p in policies:
        controls = (p.get("grantControls") or {}).get("builtInControls") or []
        if p.get("state") == "enabledForReportingButNotEnforced" and "mfa" in controls:
            out.append(_f(
                title=f"MFA policy left in report-only mode: {p.get('displayName')!r}",
                severity="medium",
                artifact=art,
                summary=(
                    f"Conditional Access policy {p.get('displayName')!r} would "
                    f"require MFA but is in report-only mode, so it is evaluated "
                    f"and logged but never enforced. Users are not actually "
                    f"protected by it."
                ),
                remediation=(
                    "Once report-only telemetry confirms no material breakage, "
                    "switch the policy state to 'enabled' to enforce MFA."
                ),
            ))
    return out


@rule
def security_defaults_and_ca_both_off(ctx: AnalyzeContext) -> list[Finding]:
    sd = ctx.graph("security-defaults")
    got = _ca_policies(ctx)
    if sd is None or got is None:
        return []
    policies, _ = got
    sd_on = bool((sd.payload or {}).get("isEnabled"))
    any_enabled_ca = any(p.get("state") == "enabled" for p in policies)
    if not sd_on and not any_enabled_ca:
        return [_f(
            title="Neither Security Defaults nor Conditional Access is active",
            severity="high",
            confidence="high",
            artifact=sd.rel,
            summary=(
                "Security Defaults are disabled and there are no enabled "
                "Conditional Access policies. The tenant has no baseline identity "
                "protection — no enforced MFA, no legacy-auth block."
            ),
            remediation=(
                "Enable Security Defaults, or (with Entra P1/P2) build Conditional "
                "Access policies enforcing MFA and blocking legacy authentication."
            ),
        )]
    return []


@rule
def excessive_global_admins(ctx: AnalyzeContext) -> list[Finding]:
    a = ctx.graph("directory-roles")
    if a is None:
        return []
    roles = a.payload.get("value", []) if isinstance(a.payload, dict) else []
    out: list[Finding] = []
    for role in roles:
        name = role.get("displayName", "")
        if name == "Global Administrator":
            members = role.get("members", []) or []
            if len(members) > 5:
                out.append(_f(
                    title=f"Excessive Global Administrators ({len(members)})",
                    severity="medium",
                    confidence="high",
                    artifact=a.rel,
                    summary=(
                        f"{len(members)} accounts hold the Global Administrator "
                        f"role. Microsoft recommends fewer than five. A large "
                        f"standing-privilege population widens the blast radius of "
                        f"any single account compromise."
                    ),
                    remediation=(
                        "Reduce Global Administrators to the minimum, use "
                        "least-privilege roles for day-to-day admin, and move "
                        "privileged access behind PIM just-in-time activation."
                    ),
                ))
    return out


@rule
def users_without_mfa_registered(ctx: AnalyzeContext) -> list[Finding]:
    a = ctx.graph("mfa-registration")
    if a is None:
        return []
    details = a.payload.get("value", []) if isinstance(a.payload, dict) else []
    if not details:
        return []
    not_registered = [
        d for d in details
        if d.get("isMfaRegistered") is False or d.get("isMfaCapable") is False
    ]
    if not_registered:
        pct = round(100 * len(not_registered) / len(details))
        sev = "high" if pct >= 25 else "medium"
        return [_f(
            title=f"{len(not_registered)} users have no MFA method registered ({pct}%)",
            severity=sev,
            confidence="high",
            artifact=a.rel,
            summary=(
                f"{len(not_registered)} of {len(details)} users ({pct}%) have not "
                f"registered a multi-factor / strong authentication method. Even "
                f"with an MFA policy, unregistered users can be enrolled by an "
                f"attacker who first phishes the password (MFA self-enrollment)."
            ),
            remediation=(
                "Drive an MFA registration campaign, enforce registration via a "
                "Conditional Access 'register security information' policy, and "
                "monitor the authentication methods registration report."
            ),
        )]
    return []


# ---- more authenticated Graph rules ------------------------------------------


_LEGACY_CLIENT_APP_TYPES = {"exchangeActiveSync", "other"}


@rule
def legacy_auth_not_blocked_by_ca(ctx: AnalyzeContext) -> list[Finding]:
    """No enabled CA policy explicitly blocks legacy-auth client types."""
    got = _ca_policies(ctx)
    if got is None:
        return []
    policies, art = got
    enabled = [p for p in policies if isinstance(p, dict) and p.get("state") == "enabled"]

    def blocks_legacy(p: dict) -> bool:
        grant = (p.get("grantControls") or {}).get("builtInControls") or []
        conditions = p.get("conditions") or {}
        client_apps = conditions.get("clientAppTypes") or []
        if not isinstance(client_apps, list):
            return False
        return "block" in grant and any(t in _LEGACY_CLIENT_APP_TYPES for t in client_apps)

    if not any(blocks_legacy(p) for p in enabled):
        return [_f(
            title="No Conditional Access policy blocks legacy authentication clients",
            severity="high",
            confidence="medium",
            artifact=art,
            summary=(
                f"None of the {len(enabled)} enabled Conditional Access policies "
                f"target legacy client app types (exchangeActiveSync/other) with a "
                f"block grant control. Legacy protocols (IMAP, POP, older Office/"
                f"ActiveSync clients) don't support modern auth or MFA, so if they "
                f"are still reachable they are a direct password-spray bypass for "
                f"any MFA policy in place."
            ),
            remediation=(
                "Add a Conditional Access policy scoped to client app types "
                "'Exchange ActiveSync' and 'Other clients' with grant control "
                "'Block', and disable legacy protocols (IMAP/POP/SMTP AUTH) in "
                "Exchange Online where they are not explicitly required."
            ),
        )]
    return []


@rule
def admins_not_covered_by_mfa_policy(ctx: AnalyzeContext) -> list[Finding]:
    """An enabled MFA-requiring CA policy exists, but privileged users may sit outside its scope."""
    got = _ca_policies(ctx)
    roles_a = ctx.graph("directory-roles")
    if got is None or roles_a is None:
        return []
    policies, art = got
    roles = roles_a.payload.get("value", []) if isinstance(roles_a.payload, dict) else []
    if not isinstance(roles, list):
        return []

    priv_role_names = {
        "Global Administrator", "Privileged Role Administrator", "Security Administrator",
        "Exchange Administrator", "SharePoint Administrator", "User Administrator",
        "Conditional Access Administrator",
    }
    priv_members: set[str] = set()
    for r in roles:
        if not isinstance(r, dict) or r.get("displayName") not in priv_role_names:
            continue
        for m in (r.get("members") or []):
            mid = m.get("id") if isinstance(m, dict) else None
            if mid:
                priv_members.add(mid)
    if not priv_members:
        return []

    def requires_mfa(p: dict) -> bool:
        controls = (p.get("grantControls") or {}).get("builtInControls") or []
        return "mfa" in controls

    def covers_privileged(p: dict) -> bool:
        users = (p.get("conditions") or {}).get("users") or {}
        include_users = users.get("includeUsers") or []
        include_roles = users.get("includeRoles") or []
        exclude_users = set(users.get("excludeUsers") or [])
        if priv_members & exclude_users:
            return False
        return "All" in include_users or bool(include_roles)

    enabled = [p for p in policies if isinstance(p, dict) and p.get("state") == "enabled"]
    mfa_policies = [p for p in enabled if requires_mfa(p)]
    if mfa_policies and not any(covers_privileged(p) for p in mfa_policies):
        return [_f(
            title="Privileged role members may not be in scope of any MFA-enforcing Conditional Access policy",
            severity="high",
            confidence="low",
            artifact=art,
            summary=(
                f"{len(priv_members)} account(s) hold a privileged directory role, "
                f"but none of the {len(mfa_policies)} enabled MFA-requiring "
                f"Conditional Access polic(y/ies) target 'All users', target "
                f"admin roles directly, or otherwise clearly include those "
                f"accounts without excluding them. Coverage could not be "
                f"confirmed from the policy's include/exclude scope."
            ),
            remediation=(
                "Verify privileged accounts are in scope of an enforced MFA "
                "policy — either scope a policy to 'All users' with no admin "
                "exclusions, or add a dedicated policy targeting privileged "
                "directory roles."
            ),
        )]
    return []


@rule
def risky_oauth2_delegated_grants(ctx: AnalyzeContext) -> list[Finding]:
    """Delegated OAuth2 grants covering sensitive scopes, per-user or tenant-wide."""
    a = ctx.graph("oauth2-grants")
    if a is None:
        return []
    grants = a.payload.get("value", []) if isinstance(a.payload, dict) else []
    if not isinstance(grants, list) or not grants:
        return []

    risky_scopes = {
        "Mail.Read", "Mail.ReadWrite", "Mail.Send", "Files.Read.All", "Files.ReadWrite.All",
        "Directory.ReadWrite.All", "Directory.AccessAsUser.All", "Contacts.ReadWrite",
        "MailboxSettings.ReadWrite", "full_access_as_app", "full_access_as_user",
        "User.ReadWrite.All", "Group.ReadWrite.All",
    }

    tenant_wide: list[tuple[dict, list[str]]] = []
    per_user: list[tuple[dict, list[str]]] = []
    for g in grants:
        if not isinstance(g, dict):
            continue
        scope_str = g.get("scope")
        if not isinstance(scope_str, str) or not scope_str.strip():
            continue
        matched = sorted({s for s in scope_str.split() if s in risky_scopes})
        if not matched:
            continue
        if g.get("consentType") == "AllPrincipals":
            tenant_wide.append((g, matched))
        else:
            per_user.append((g, matched))

    out: list[Finding] = []
    if tenant_wide:
        clients = sorted({g.get("clientId", "?") for g, _ in tenant_wide})
        out.append(_f(
            title=f"Tenant-wide OAuth2 consent grants sensitive delegated scopes ({len(tenant_wide)})",
            severity="high",
            confidence="medium",
            artifact=a.rel,
            summary=(
                f"{len(tenant_wide)} OAuth2 permission grant(s) with consentType "
                f"'AllPrincipals' cover sensitive scopes (e.g. mail, files, or "
                f"directory write access), applying to every user in the tenant. "
                f"Client application id(s): {', '.join(clients)}. A single "
                f"compromised or malicious app with this consent can read/exfil "
                f"data across the whole org."
            ),
            remediation=(
                "Review these app registrations/service principals in Enterprise "
                "Applications, confirm business need for the scope breadth, and "
                "revoke or narrow tenant-wide consent for apps that don't need it."
            ),
        ))
    if per_user:
        out.append(_f(
            title=f"Individual users have granted OAuth apps sensitive delegated scopes ({len(per_user)})",
            severity="medium",
            confidence="medium",
            artifact=a.rel,
            summary=(
                f"{len(per_user)} delegated OAuth2 grant(s) from individual users "
                f"cover sensitive scopes (e.g. mail, files, or directory write "
                f"access). If user consent to third-party apps is unrestricted, "
                f"this is a common phishing vector (illicit consent grant)."
            ),
            remediation=(
                "Audit the listed grants for legitimacy, revoke any unrecognized "
                "or unnecessary ones, and restrict user consent to verified "
                "publishers or admin-only consent for high-privilege scopes."
            ),
        ))
    return out


def _cred_end_dt(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


@rule
def app_credentials_expired_or_long_lived(ctx: AnalyzeContext) -> list[Finding]:
    """App registration secrets/certs that are already expired, or valid for >2 years."""
    a = ctx.graph("app-registrations")
    if a is None:
        return []
    apps = a.payload.get("value", []) if isinstance(a.payload, dict) else []
    if not isinstance(apps, list) or not apps:
        return []

    now = datetime.now(timezone.utc)
    expired_apps: set[str] = set()
    long_lived_apps: set[str] = set()
    for app in apps:
        if not isinstance(app, dict):
            continue
        name = app.get("displayName") or app.get("appId") or "unknown app"
        creds = list(app.get("passwordCredentials") or []) + list(app.get("keyCredentials") or [])
        for c in creds:
            if not isinstance(c, dict):
                continue
            end_dt = _cred_end_dt(c.get("endDateTime"))
            if end_dt is None:
                continue
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=timezone.utc)
            if end_dt < now:
                expired_apps.add(name)
            elif (end_dt - now).days > 730:
                long_lived_apps.add(name)

    out: list[Finding] = []
    if expired_apps:
        out.append(_f(
            title=f"App registrations retain expired credentials ({len(expired_apps)})",
            severity="medium",
            confidence="medium",
            artifact=a.rel,
            summary=(
                f"{len(expired_apps)} app registration(s) still list expired "
                f"password/certificate credentials: {', '.join(sorted(expired_apps))}. "
                f"Expired credentials cannot authenticate, but their continued "
                f"presence usually indicates an unmaintained/orphaned app "
                f"registration that may still hold live API permissions."
            ),
            remediation=(
                "Review each app for continued business need; remove expired "
                "credential entries and decommission/rotate any app that is no "
                "longer maintained but still holds permissions."
            ),
        ))
    if long_lived_apps:
        out.append(_f(
            title=f"App registrations have credentials valid for more than 2 years ({len(long_lived_apps)})",
            severity="medium",
            confidence="medium",
            artifact=a.rel,
            summary=(
                f"{len(long_lived_apps)} app registration(s) have a secret or "
                f"certificate valid for more than 2 years from now: "
                f"{', '.join(sorted(long_lived_apps))}. Long-lived credentials "
                f"widen the window an attacker can use a leaked secret before it "
                f"naturally expires."
            ),
            remediation=(
                "Reissue app credentials with a short expiry (<=6-12 months), "
                "prefer certificate-based or workload-identity-federation auth "
                "over long-lived client secrets, and rotate on a schedule."
            ),
        ))
    return out


@rule
def guests_present_and_in_privileged_roles(ctx: AnalyzeContext) -> list[Finding]:
    """Guest (B2B external) users exist, and/or hold a privileged directory role."""
    guests_a = ctx.graph("guest-users")
    if guests_a is None:
        return []
    guests = guests_a.payload.get("value", []) if isinstance(guests_a.payload, dict) else []
    if not isinstance(guests, list) or not guests:
        return []

    out: list[Finding] = []
    roles_a = ctx.graph("directory-roles")
    if roles_a is not None:
        roles = roles_a.payload.get("value", []) if isinstance(roles_a.payload, dict) else []
        guest_ids = {g.get("id") for g in guests if isinstance(g, dict) and g.get("id")}
        priv_hits: set[str] = set()
        if isinstance(roles, list) and guest_ids:
            for r in roles:
                if not isinstance(r, dict):
                    continue
                for m in (r.get("members") or []):
                    mid = m.get("id") if isinstance(m, dict) else None
                    if mid and mid in guest_ids:
                        priv_hits.add(r.get("displayName") or "unknown role")
        if priv_hits:
            out.append(_f(
                title=f"Guest account(s) hold privileged directory role(s): {', '.join(sorted(priv_hits))}",
                severity="high",
                confidence="high",
                artifact=roles_a.rel,
                summary=(
                    "One or more external (B2B guest) identities are members of "
                    "a privileged directory role. Guest accounts are authenticated "
                    "by their home tenant, which FullCheck's target tenant does "
                    "not control, so privileged guest access extends the trust "
                    "boundary outside the organization."
                ),
                remediation=(
                    "Remove standing privileged roles from guest accounts; if "
                    "external admin access is required, use PIM for Groups / "
                    "time-bound eligible assignments and review regularly."
                ),
            ))

    out.append(_f(
        title=f"Guest (external) users present in tenant ({len(guests)})",
        severity="low",
        confidence="high",
        artifact=guests_a.rel,
        summary=(
            f"{len(guests)} guest user account(s) exist in the directory. Guest "
            f"access is a normal collaboration feature but expands the "
            f"authentication and data-sharing boundary beyond employees."
        ),
        remediation=(
            "Periodically review guest accounts for staleness (access reviews), "
            "restrict guest invitations to specific domains/admins, and confirm "
            "guests only reach the resources they were invited to collaborate on."
        ),
    ))
    return out


@rule
def user_consent_to_apps_allowed(ctx: AnalyzeContext) -> list[Finding]:
    """Tenant's authorization policy still allows end users to consent to third-party apps."""
    a = ctx.graph("authorization-policy")
    if a is None:
        return []
    policy = a.payload if isinstance(a.payload, dict) else {}
    perms = policy.get("defaultUserRolePermissions")
    if not isinstance(perms, dict):
        return []
    assigned = perms.get("permissionGrantPoliciesAssigned")
    if not isinstance(assigned, list) or not assigned:
        return []
    if any("user-default" in str(x) or "microsoft-user-default" in str(x) for x in assigned):
        return [_f(
            title="Users are permitted to consent to third-party OAuth applications",
            severity="medium",
            confidence="medium",
            artifact=a.rel,
            summary=(
                f"The tenant's authorization policy assigns default user "
                f"permission grant policy/ies ({assigned!r}) that allow standard "
                f"users to consent to third-party OAuth applications without "
                f"admin review. This is the primary path for illicit consent "
                f"grant phishing."
            ),
            remediation=(
                "Restrict user consent to verified publishers with low-risk "
                "scopes only (or disable it entirely) and route higher-risk "
                "requests through the admin consent workflow."
            ),
        )]
    return []


@rule
def admin_consent_workflow_disabled(ctx: AnalyzeContext) -> list[Finding]:
    """Admin consent request workflow is turned off — users with blocked consent have no safe path."""
    a = ctx.graph("admin-consent-policy")
    if a is None:
        return []
    payload = a.payload if isinstance(a.payload, dict) else {}
    if payload.get("isEnabled") is False:
        return [_f(
            title="Admin consent request workflow is disabled",
            severity="low",
            confidence="medium",
            artifact=a.rel,
            summary=(
                "The admin consent workflow is disabled. If user consent to "
                "apps is also restricted, users who need a new app approved "
                "have no in-product way to request review, which tends to "
                "produce informal/undocumented approvals outside Entra."
            ),
            remediation=(
                "Enable the admin consent workflow (Entra ID > Enterprise "
                "applications > Consent and permissions) and assign reviewers, "
                "so blocked consent requests are captured and auditable."
            ),
        )]
    return []


_WEAK_MFA_METHODS = {
    "mobilePhone", "alternateMobilePhone", "officePhone", "sms",
    "voiceMobile", "voiceAlternateMobile", "voiceOffice",
}
_STRONG_MFA_METHODS = {
    "microsoftAuthenticatorPasswordless", "windowsHelloForBusiness",
    "fido2", "x509CertificateMultiFactor",
}


@rule
def weak_mfa_methods_only(ctx: AnalyzeContext) -> list[Finding]:
    """Users who registered MFA, but only phone/SMS methods (no phishing-resistant method)."""
    a = ctx.graph("mfa-registration")
    if a is None:
        return []
    details = a.payload.get("value", []) if isinstance(a.payload, dict) else []
    if not isinstance(details, list) or not details:
        return []
    weak_only = []
    for d in details:
        if not isinstance(d, dict):
            continue
        methods = d.get("methodsRegistered")
        if not isinstance(methods, list) or not methods:
            continue
        methods_set = set(methods)
        if methods_set & _WEAK_MFA_METHODS and not (methods_set & _STRONG_MFA_METHODS):
            weak_only.append(d.get("userPrincipalName") or "unknown")
    if weak_only:
        return [_f(
            title=f"Users rely only on weak MFA methods such as SMS/voice ({len(weak_only)})",
            severity="low",
            confidence="medium",
            artifact=a.rel,
            summary=(
                f"{len(weak_only)} user(s) have only phone-based (SMS/voice call) "
                f"MFA methods registered, with no phishing-resistant method "
                f"(Authenticator passthrough, Windows Hello, FIDO2, or "
                f"certificate). Phone-based MFA is vulnerable to SIM-swap and "
                f"real-time phishing/AiTM relay."
            ),
            remediation=(
                "Encourage/require migration to phishing-resistant methods "
                "(FIDO2 security keys, Authenticator passwordless, or "
                "certificate-based auth) and phase out SMS/voice as a factor "
                "for privileged or high-value accounts first."
            ),
        )]
    return []


@rule
def unresolved_risky_users(ctx: AnalyzeContext) -> list[Finding]:
    """Entra ID Protection users flagged 'atRisk' with no remediation recorded."""
    a = ctx.graph("risky-users")
    if a is None:
        return []
    users = a.payload.get("value", []) if isinstance(a.payload, dict) else []
    if not isinstance(users, list) or not users:
        return []
    at_risk = [u for u in users if isinstance(u, dict) and u.get("riskState") == "atRisk"]
    if not at_risk:
        return []
    sev = "high" if any(u.get("riskLevel") == "high" for u in at_risk) else "medium"
    return [_f(
        title=f"Unresolved at-risk user accounts in Entra ID Protection ({len(at_risk)})",
        severity=sev,
        confidence="high",
        artifact=a.rel,
        summary=(
            f"{len(at_risk)} of {len(users)} user(s) evaluated by Entra ID "
            f"Protection are in riskState 'atRisk' (not yet remediated or "
            f"dismissed). This reflects detections such as leaked credentials, "
            f"impossible travel, or anomalous sign-ins that have not been acted "
            f"on."
        ),
        remediation=(
            "Investigate each at-risk user in Entra ID Protection, force a "
            "password reset and MFA re-registration where warranted, and "
            "configure a user-risk Conditional Access policy to automate "
            "response going forward."
        ),
    )]


@rule
def broad_dynamic_or_public_groups(ctx: AnalyzeContext) -> list[Finding]:
    """Dynamic-membership or public-visibility groups that can silently widen access."""
    a = ctx.graph("groups")
    if a is None:
        return []
    groups = a.payload.get("value", []) if isinstance(a.payload, dict) else []
    if not isinstance(groups, list) or not groups:
        return []

    dynamic = [
        g for g in groups
        if isinstance(g, dict)
        and isinstance(g.get("groupTypes"), list) and "DynamicMembership" in g["groupTypes"]
        and g.get("membershipRule")
    ]
    public = [
        g for g in groups
        if isinstance(g, dict) and str(g.get("visibility", "")).lower() == "public"
    ]

    out: list[Finding] = []
    if dynamic:
        out.append(_f(
            title=f"Dynamic-membership groups present ({len(dynamic)})",
            severity="info",
            confidence="medium",
            artifact=a.rel,
            summary=(
                f"{len(dynamic)} group(s) use a dynamic membership rule, "
                f"meaning membership (and any access/roles granted through the "
                f"group) changes automatically as directory attributes change. "
                f"A loosely written rule can silently add unintended members."
            ),
            remediation=(
                "Review dynamic membership rules for over-broad attribute "
                "matches, and audit what access (group-based licensing, app "
                "roles, or role-assignable groups) each dynamic group grants."
            ),
        ))
    if public:
        out.append(_f(
            title=f"Public-visibility Microsoft 365 groups present ({len(public)})",
            severity="low",
            confidence="medium",
            artifact=a.rel,
            summary=(
                f"{len(public)} Microsoft 365 group(s) are set to 'Public' "
                f"visibility, meaning any tenant member can join without "
                f"owner approval and can see the group's conversations/files."
            ),
            remediation=(
                "Set groups containing sensitive content or discussions to "
                "'Private', and review tenant-wide group creation/visibility "
                "defaults."
            ),
        ))
    return out


@rule
def noncompliant_devices_present(ctx: AnalyzeContext) -> list[Finding]:
    """Devices registered in Entra that Intune/compliance policy marks non-compliant."""
    a = ctx.graph("devices")
    if a is None:
        return []
    devices = a.payload.get("value", []) if isinstance(a.payload, dict) else []
    if not isinstance(devices, list) or not devices:
        return []
    noncompliant = [d for d in devices if isinstance(d, dict) and d.get("isCompliant") is False]
    if not noncompliant:
        return []
    pct = round(100 * len(noncompliant) / len(devices))
    sev = "low" if pct >= 25 else "info"
    return [_f(
        title=f"Non-compliant devices registered in Entra ({len(noncompliant)} of {len(devices)}, {pct}%)",
        severity=sev,
        confidence="medium",
        artifact=a.rel,
        summary=(
            f"{len(noncompliant)} of {len(devices)} registered device(s) are "
            f"marked non-compliant against the tenant's device compliance "
            f"policy. If Conditional Access grants access based on device "
            f"compliance, these devices either fail that check (reducing "
            f"usability) or compliance isn't actually being enforced as a "
            f"CA condition."
        ),
        remediation=(
            "Investigate why the devices are non-compliant (missing policy "
            "settings, unmanaged/BYOD, stale check-in) and confirm high-value "
            "resources require a 'device marked as compliant' Conditional "
            "Access grant control."
        ),
    )]


@rule
def break_glass_account_hygiene(ctx: AnalyzeContext) -> list[Finding]:
    """Too few Global Administrators risks a lockout with no working emergency access account."""
    a = ctx.graph("directory-roles")
    if a is None:
        return []
    roles = a.payload.get("value", []) if isinstance(a.payload, dict) else []
    if not isinstance(roles, list) or not roles:
        return []
    for role in roles:
        if not isinstance(role, dict) or role.get("displayName") != "Global Administrator":
            continue
        members = role.get("members") or []
        if not isinstance(members, list):
            return []
        if len(members) <= 1:
            return [_f(
                title=f"Too few Global Administrators for break-glass resilience ({len(members)})",
                severity="info",
                confidence="medium",
                artifact=a.rel,
                summary=(
                    f"Only {len(members)} account(s) hold the Global "
                    f"Administrator role. While excessive admin count is its "
                    f"own risk, having only zero or one means a single "
                    f"disabled/locked/MFA-broken account can leave the tenant "
                    f"with no working Global Administrator."
                ),
                remediation=(
                    "Maintain at least two dedicated cloud-only 'break-glass' "
                    "emergency access accounts, excluded from Conditional "
                    "Access and MFA registration requirements but with a very "
                    "strong credential, monitored closely for any sign-in."
                ),
            )]
    return []
