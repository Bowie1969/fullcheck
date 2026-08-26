"""The SCAN-tier Microsoft Graph checks — read-only endpoints to pull.

Each register_check(GraphCheck(...)) entry names a read-only Graph path and the
delegated/app permission it needs. graph.run_scan iterates them; a missing scope
surfaces as one skipped check. Add coverage by appending register_check calls.
Everything here MUST be a GET (read-only) — active/write operations belong in
catalog.py behind the ApprovalGate.
"""

from __future__ import annotations

from .graph import GraphCheck, register_check

# Identity posture ------------------------------------------------------------
register_check(GraphCheck(
    key="ca-policies",
    path="/identity/conditionalAccessPolicies",
    scope="Policy.Read.All",
))
register_check(GraphCheck(
    key="authorization-policy",
    path="/policies/authorizationPolicy",
    scope="Policy.Read.All",
    paginate=False,
))
register_check(GraphCheck(
    key="security-defaults",
    path="/policies/identitySecurityDefaultsEnforcementPolicy",
    scope="Policy.Read.All",
    paginate=False,
))

# MFA / auth-method registration ---------------------------------------------
register_check(GraphCheck(
    key="mfa-registration",
    path="/reports/authenticationMethods/userRegistrationDetails",
    scope="AuditLog.Read.All / Reports.Read.All",
))

# Privileged access -----------------------------------------------------------
register_check(GraphCheck(
    key="directory-roles",
    path="/directoryRoles?$expand=members",
    scope="RoleManagement.Read.Directory / Directory.Read.All",
))

# Tenant shape ----------------------------------------------------------------
register_check(GraphCheck(
    key="organization",
    path="/organization",
    scope="Organization.Read.All / Directory.Read.All",
))
register_check(GraphCheck(
    key="domains",
    path="/domains",
    scope="Domain.Read.All / Directory.Read.All",
))
register_check(GraphCheck(
    key="users",
    path="/users?$select=id,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity",
    scope="User.Read.All / AuditLog.Read.All (for signInActivity)",
))
register_check(GraphCheck(
    key="guest-users",
    path="/users?$filter=userType eq 'Guest'&$select=id,userPrincipalName,createdDateTime,signInActivity",
    scope="User.Read.All / AuditLog.Read.All (for signInActivity)",
))
register_check(GraphCheck(
    key="groups",
    path="/groups?$select=id,displayName,groupTypes,membershipRule,visibility",
    scope="Group.Read.All / Directory.Read.All",
))
register_check(GraphCheck(
    key="devices",
    path="/devices?$select=id,displayName,operatingSystem,isCompliant,trustType",
    scope="Device.Read.All / Directory.Read.All",
))

# App / SP attack surface ------------------------------------------------------
register_check(GraphCheck(
    key="app-registrations",
    path="/applications",
    scope="Application.Read.All",
))
register_check(GraphCheck(
    key="service-principals",
    path="/servicePrincipals",
    scope="Application.Read.All / Directory.Read.All",
))
register_check(GraphCheck(
    key="oauth2-grants",
    path="/oauth2PermissionGrants",
    scope="DelegatedPermissionGrant.Read.All",
))

# Privileged access (PIM) ------------------------------------------------------
register_check(GraphCheck(
    key="pim-eligible",
    path="/roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal",
    scope="RoleEligibilitySchedule.Read.Directory / RoleManagement.Read.Directory",
))

# Identity Protection -----------------------------------------------------------
register_check(GraphCheck(
    key="risky-users",
    path="/identityProtection/riskyUsers",
    scope="IdentityRiskyUser.Read.All (requires Entra ID P2)",
))
register_check(GraphCheck(
    key="risk-detections",
    path="/identityProtection/riskDetections",
    scope="IdentityRiskEvent.Read.All (requires Entra ID P2)",
))

# Conditional Access supporting objects ----------------------------------------
register_check(GraphCheck(
    key="named-locations",
    path="/identity/conditionalAccess/namedLocations",
    scope="Policy.Read.All",
))
register_check(GraphCheck(
    key="cross-tenant-access",
    path="/policies/crossTenantAccessPolicy/default",
    scope="Policy.Read.All / CrossTenantInformation.Read.All",
    paginate=False,
))
register_check(GraphCheck(
    key="admin-consent-policy",
    path="/policies/adminConsentRequestPolicy",
    scope="Policy.Read.All",
    paginate=False,
))
register_check(GraphCheck(
    key="auth-methods-policy",
    path="/policies/authenticationMethodsPolicy",
    scope="Policy.Read.All",
    paginate=False,
))
register_check(GraphCheck(
    key="permission-grant-policies",
    path="/policies/permissionGrantPolicies",
    scope="Policy.Read.All",
))

# Audit trail -------------------------------------------------------------------
register_check(GraphCheck(
    key="directory-audit",
    path="/auditLogs/directoryAudits?$top=50",
    scope="AuditLog.Read.All",
))

# Licensing / roles reference table --------------------------------------------
register_check(GraphCheck(
    key="subscribed-skus",
    path="/subscribedSkus",
    scope="Organization.Read.All / Directory.Read.All",
))
register_check(GraphCheck(
    key="directory-role-templates",
    path="/directoryRoleTemplates",
    scope="RoleManagement.Read.Directory / Directory.Read.All",
))
