"""Unauthenticated M365/Entra recon probes (PASSIVE + PROBE tiers).

Every class here subclasses base.M365Probe and is registered with @register_probe.
They hit only Microsoft's shared, unauthenticated endpoints and NEVER send a
password or attempt a sign-in. See base.py for the contract.
"""

from __future__ import annotations

import re
import socket
from typing import Any
from urllib.parse import urlparse

import httpx

from ..action import BlastRadius
from .base import (
    AUTODISCOVER,
    LOGIN,
    M365Probe,
    polite_sleep,
    register_probe,
)

# A benign, almost-certainly-nonexistent probe local-part for realm/tenant checks
# that need *a* UPN but must not target a real person.
PROBE_USER = "aadprobe_donotexist"


@register_probe
class TenantOpenIdConfig(M365Probe):
    """Does this domain back an Entra tenant, and what's its tenant id/region?

    The v2.0 OpenID configuration is public and unauthenticated. Its `issuer`
    carries the tenant GUID; absence (400) means the domain isn't Entra-backed.
    """

    name = "m365-openid-config"
    blast_radius = BlastRadius.PASSIVE

    def collect(self, domain: str, params: dict, http: httpx.Client) -> dict[str, Any]:
        url = f"{LOGIN}/{domain}/v2.0/.well-known/openid-configuration"
        out: dict[str, Any] = {"domain": domain, "url": url}
        try:
            r = http.get(url)
            out["status_code"] = r.status_code
            if r.status_code == 200:
                body = r.json()
                issuer = body.get("issuer", "")
                out["issuer"] = issuer
                out["tenant_region_scope"] = body.get("tenant_region_scope")
                out["cloud_instance"] = body.get("cloud_instance_name")
                # issuer looks like https://login.microsoftonline.com/<guid>/v2.0
                parts = [p for p in issuer.split("/") if p]
                out["tenant_id"] = parts[-2] if len(parts) >= 2 else None
                out["tenant_exists"] = True
            else:
                out["tenant_exists"] = False
        except httpx.HTTPError as e:
            out["error"] = str(e)
        return out


@register_probe
class UserRealm(M365Probe):
    """Managed vs Federated, and (if federated) the on-prem auth URL / brand.

    getuserrealm.srf is unauthenticated and takes only a UPN shape — we send a
    benign non-account local-part. Federated tenants expose an ADFS AuthURL,
    which is an attack-surface signal (ADFS is internet-facing and juicy).
    """

    name = "m365-userrealm"
    blast_radius = BlastRadius.PASSIVE

    def collect(self, domain: str, params: dict, http: httpx.Client) -> dict[str, Any]:
        login = f"{PROBE_USER}@{domain}"
        url = f"{LOGIN}/getuserrealm.srf?login={login}&json=1"
        out: dict[str, Any] = {"domain": domain, "probe_upn": login}
        try:
            r = http.get(url)
            out["status_code"] = r.status_code
            if r.status_code == 200:
                body = r.json()
                out["namespace_type"] = body.get("NameSpaceType")
                out["federation_brand"] = body.get("FederationBrandName")
                out["auth_url"] = body.get("AuthURL")
                out["domain_name"] = body.get("DomainName")
                out["cloud_instance"] = body.get("CloudInstanceName")
                out["is_federated"] = body.get("NameSpaceType") == "Federated"
        except httpx.HTTPError as e:
            out["error"] = str(e)
        return out


@register_probe
class TenantFederationDomains(M365Probe):
    """All domains attached to the tenant, via the Autodiscover SOAP
    GetFederationInformation call. Surfaces the *.onmicrosoft.com name and any
    sibling domains sharing the tenant — useful scope/attack-surface context.
    Unauthenticated; reads only tenant metadata.
    """

    name = "m365-tenant-domains"
    blast_radius = BlastRadius.PASSIVE

    _SOAP = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" '
        'xmlns:a="http://www.w3.org/2005/08/addressing" '
        'xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'
        "<soap:Header>"
        "<a:Action soap:mustUnderstand=\"1\">"
        "http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"
        "</a:Action>"
        "<a:To soap:mustUnderstand=\"1\">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>"
        "<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>"
        "</soap:Header>"
        "<soap:Body>"
        '<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">'
        '<Request><Domain>{domain}</Domain></Request>'
        "</GetFederationInformationRequestMessage>"
        "</soap:Body></soap:Envelope>"
    )

    def collect(self, domain: str, params: dict, http: httpx.Client) -> dict[str, Any]:
        url = f"{AUTODISCOVER}/autodiscover/autodiscover.svc"
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "User-Agent": "AutodiscoverClient",
            "SOAPAction": (
                '"http://schemas.microsoft.com/exchange/2010/Autodiscover/'
                'Autodiscover/GetFederationInformation"'
            ),
        }
        out: dict[str, Any] = {"domain": domain}
        try:
            r = http.post(url, content=self._SOAP.format(domain=domain), headers=headers)
            out["status_code"] = r.status_code
            # crude but dependency-free: pull <Domain>...</Domain> out of the XML
            text = r.text
            domains: list[str] = []
            marker = "<Domain>"
            end = "</Domain>"
            i = text.find(marker)
            while i != -1:
                j = text.find(end, i)
                if j == -1:
                    break
                domains.append(text[i + len(marker):j])
                i = text.find(marker, j)
            out["domains"] = sorted(set(domains))
            out["onmicrosoft"] = [d for d in out["domains"] if d.endswith(".onmicrosoft.com")]
        except httpx.HTTPError as e:
            out["error"] = str(e)
        return out


@register_probe
class UserEnumeration(M365Probe):
    """Validate candidate accounts via GetCredentialType — WITHOUT a password.

    IfExistsResult: 0 = account exists, 1 = does not, 5 = exists on a different
    identity provider, 6 = throttled/uncertain. No credential is ever sent, so no
    lockout — but it is logged and alertable, hence PROBE tier + a politeness
    delay between candidates. Supply candidates via params['users'] (a file path,
    one UPN or local-part per line); local-parts get @domain appended.
    """

    name = "m365-user-enum"
    blast_radius = BlastRadius.PROBE

    def collect(self, domain: str, params: dict, http: httpx.Client) -> dict[str, Any]:
        from pathlib import Path

        users_file = params.get("users")
        out: dict[str, Any] = {"domain": domain, "results": []}
        if not users_file:
            out["error"] = "no params['users'] file supplied — nothing to enumerate"
            return out
        p = Path(users_file)
        if not p.exists():
            out["error"] = f"users file not found: {users_file}"
            return out
        url = f"{LOGIN}/common/GetCredentialType?mkt=en-US"
        candidates = [
            ln.strip() for ln in p.read_text().splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        for i, cand in enumerate(candidates):
            upn = cand if "@" in cand else f"{cand}@{domain}"
            rec: dict[str, Any] = {"upn": upn}
            try:
                r = http.post(url, json={"Username": upn, "isOtherIdpSupported": True})
                rec["status_code"] = r.status_code
                if r.status_code == 200:
                    body = r.json()
                    ifx = body.get("IfExistsResult")
                    rec["if_exists_result"] = ifx
                    rec["throttle_status"] = body.get("ThrottleStatus")
                    rec["exists"] = ifx in (0, 6)
            except httpx.HTTPError as e:
                rec["error"] = str(e)
            out["results"].append(rec)
            if i < len(candidates) - 1:
                polite_sleep()
        out["valid"] = [r["upn"] for r in out["results"] if r.get("exists")]
        out["valid_count"] = len(out["valid"])
        return out


# ---- additional unauth probes (v0.2 M365 module expansion) ------------------
#
# Everything below follows the same rule as everything above: unauthenticated
# endpoints only, no password, no sign-in attempt, defensive collect(). Tier is
# PASSIVE unless a probe tests a *specific real* account (it never does here —
# where a UPN shape is required we reuse the same benign PROBE_USER as
# UserRealm) or otherwise performs auth-flow traffic beyond a bare GET.


@register_probe
class TenantBranding(M365Probe):
    """Company branding leaked by the tenant-specific sign-in page.

    A GET to the v2.0 authorize endpoint for a *specific* tenant (rather than
    /common), using a well-known public first-party client id (Azure CLI's —
    documented by Microsoft, pre-consented in every tenant, not a secret),
    renders that tenant's customised sign-in page: logo, illustration,
    background colour, boilerplate text — all before any credential is
    entered. This is why phishing kits can pixel-match a target's branding
    without ever authenticating. Field extraction is best-effort (Microsoft
    can reshape the embedded config at any time); the raw status/length are
    recorded regardless so the probe is useful even when parsing finds
    nothing. Pure GET, no username, no secret sent: PASSIVE.
    """

    name = "m365-tenant-branding"
    blast_radius = BlastRadius.PASSIVE

    # Azure CLI's public client id (Microsoft Learn: "commonly used Microsoft
    # application IDs"). Public by design — every tenant pre-consents it.
    _PUBLIC_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
    _FIELDS = ("BannerLogo", "Illustration", "BackgroundColor", "BoilerPlateText", "UserIdLabel")

    def collect(self, domain: str, params: dict, http: httpx.Client) -> dict[str, Any]:
        url = (
            f"{LOGIN}/{domain}/oauth2/v2.0/authorize"
            f"?client_id={self._PUBLIC_CLIENT_ID}&response_type=code"
            "&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient"
            "&scope=openid"
        )
        out: dict[str, Any] = {"domain": domain, "url": url}
        try:
            r = http.get(url)
            out["status_code"] = r.status_code
            text = r.text
            out["content_length"] = len(text)
            found: dict[str, str] = {}
            for field in self._FIELDS:
                m = re.search(rf'"{field}"\s*:\s*"([^"]*)"', text)
                if m and m.group(1):
                    found[field] = m.group(1)
            out["branding_fields"] = found
            out["has_custom_branding"] = bool(found)
            out["note"] = "field extraction is best-effort; status/length are the reliable signal"
        except httpx.HTTPError as e:
            out["error"] = str(e)
        return out


@register_probe
class OAuthAuthorizeReachability(M365Probe):
    """Confirms tenant validity via the AADSTS error code from /authorize.

    A GET to the v2.0 authorize endpoint with an all-zero client id (never a
    real app registration) always fails — but *how* it fails is a documented,
    stable signal: AADSTS90002 ("Tenant '<domain>' not found") means the
    domain isn't Entra-backed at all, while AADSTS700016 ("Application ...
    was not found in the directory '<tenant>'") confirms the tenant exists
    and echoes its resolved name/id in the same error page. This is a useful
    cross-check against TenantOpenIdConfig on domains that proxy or rewrite
    the well-known metadata path. No client secret, no username, nothing but
    a GET: PASSIVE.
    """

    name = "m365-oauth-authorize"
    blast_radius = BlastRadius.PASSIVE

    _NULL_CLIENT_ID = "00000000-0000-0000-0000-000000000000"

    def collect(self, domain: str, params: dict, http: httpx.Client) -> dict[str, Any]:
        url = (
            f"{LOGIN}/{domain}/oauth2/v2.0/authorize"
            f"?client_id={self._NULL_CLIENT_ID}&response_type=code"
            "&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient"
        )
        out: dict[str, Any] = {"domain": domain, "url": url}
        try:
            r = http.get(url)
            out["status_code"] = r.status_code
            m = re.search(r"(AADSTS\d+)", r.text)
            code = m.group(1) if m else None
            out["aadsts_code"] = code
            out["tenant_not_found"] = code == "AADSTS90002"
            out["tenant_confirmed"] = code in ("AADSTS700016", "AADSTS650053")
        except httpx.HTTPError as e:
            out["error"] = str(e)
        return out


@register_probe
class ADFSFederationMetadata(M365Probe):
    """When a domain is federated, fingerprint the on-prem ADFS behind it.

    Re-resolves NameSpaceType via getuserrealm.srf (same benign PROBE_USER as
    UserRealm) to find the AuthURL host, then pulls two purely-metadata ADFS
    endpoints an ADFS server publishes for every relying party to consume:
    FederationMetadata.xml (WS-Federation metadata — always public) and a bare
    GET of /adfs/ls/ (status + server headers only — never posts a form or
    credential). PASSIVE: metadata documents, not a sign-in attempt.
    """

    name = "m365-adfs-metadata"
    blast_radius = BlastRadius.PASSIVE

    def collect(self, domain: str, params: dict, http: httpx.Client) -> dict[str, Any]:
        out: dict[str, Any] = {"domain": domain}
        realm_url = f"{LOGIN}/getuserrealm.srf?login={PROBE_USER}@{domain}&json=1"
        try:
            r = http.get(realm_url)
            if r.status_code != 200:
                out["error"] = f"getuserrealm.srf returned {r.status_code}"
                return out
            body = r.json()
        except httpx.HTTPError as e:
            out["error"] = str(e)
            return out

        auth_url = body.get("AuthURL")
        out["is_federated"] = body.get("NameSpaceType") == "Federated"
        out["auth_url"] = auth_url
        if not auth_url:
            out["note"] = "not federated (or no AuthURL) — nothing on-prem to fingerprint"
            return out

        host = urlparse(auth_url).netloc
        out["adfs_host"] = host

        meta_url = f"https://{host}/FederationMetadata/2007-06/FederationMetadata.xml"
        try:
            r = http.get(meta_url)
            out["federation_metadata_status"] = r.status_code
            if r.status_code == 200:
                m = re.search(r'entityID="([^"]+)"', r.text)
                out["federation_metadata_entity_id"] = m.group(1) if m else None
                out["looks_like_adfs"] = "adfs" in r.text.lower()
        except httpx.HTTPError as e:
            out["federation_metadata_error"] = str(e)

        polite_sleep()

        ls_url = f"https://{host}/adfs/ls/"
        try:
            r = http.get(ls_url)
            out["adfs_ls_status"] = r.status_code
            out["adfs_ls_server_header"] = r.headers.get("Server")
            out["adfs_ls_xpoweredby"] = r.headers.get("X-Powered-By")
        except httpx.HTTPError as e:
            out["adfs_ls_error"] = str(e)
        return out


@register_probe
class DNSPosture(M365Probe):
    """Cloud-mail / device-management DNS fingerprints, stdlib resolver only.

    Existence and CNAME-target of a handful of hostnames reliably signals M365
    adoption: autodiscover (Exchange Online mail flow), enterpriseregistration
    / enterpriseenrollment (Entra hybrid join / Intune MDM), msoid (legacy
    Entra sign-in), lyncdiscover/sip (Skype for Business/Teams), and the DKIM
    selector1/2._domainkey CNAMEs (Exchange Online outbound mail signing).
    `socket.gethostbyname_ex` is the stdlib primitive available for this — it
    follows CNAMEs and returns the canonical name, but it cannot do TXT or MX
    lookups (those aren't address records). SPF/DMARC/MX therefore cannot be
    read without a record-type-aware resolver (e.g. dnspython), which is not a
    project dependency, so that's recorded as an honest skip rather than
    guessed at. Public DNS resolution only, no traffic to the target's own
    infrastructure: PASSIVE.
    """

    name = "m365-dns-posture"
    blast_radius = BlastRadius.PASSIVE

    _HOSTS = {
        "autodiscover": "autodiscover.{domain}",
        "enterpriseregistration": "enterpriseregistration.{domain}",
        "enterpriseenrollment": "enterpriseenrollment.{domain}",
        "msoid": "msoid.{domain}",
        "lyncdiscover": "lyncdiscover.{domain}",
        "sip": "sip.{domain}",
        "dkim_selector1": "selector1._domainkey.{domain}",
        "dkim_selector2": "selector2._domainkey.{domain}",
    }

    # Substring expected in the canonical name / aliases when the hostname is
    # genuinely delegated to Microsoft, vs. some unrelated CNAME target.
    _EXPECT = {
        "autodiscover": "outlook.com",
        "enterpriseregistration": "windows.net",
        "enterpriseenrollment": "manage.microsoft.com",
        "lyncdiscover": "online.lync.com",
        "sip": "online.lync.com",
        "dkim_selector1": "onmicrosoft.com",
        "dkim_selector2": "onmicrosoft.com",
    }

    def collect(self, domain: str, params: dict, http: httpx.Client) -> dict[str, Any]:
        out: dict[str, Any] = {"domain": domain, "records": {}}
        for key, tmpl in self._HOSTS.items():
            host = tmpl.format(domain=domain)
            rec: dict[str, Any] = {"host": host}
            try:
                canonical, aliases, addrs = socket.gethostbyname_ex(host)
                rec["resolves"] = True
                rec["canonical_name"] = canonical
                rec["aliases"] = aliases
                rec["addresses"] = addrs
                expect = self._EXPECT.get(key)
                if expect:
                    rec["matches_microsoft"] = expect in canonical or any(expect in a for a in aliases)
            except socket.gaierror as e:
                rec["resolves"] = False
                rec["error"] = str(e)
            except OSError as e:
                rec["resolves"] = False
                rec["error"] = str(e)
            out["records"][key] = rec
        out["mx_spf_dmarc"] = {
            "note": (
                "MX/TXT/SPF/DMARC lookups need a record-type-aware resolver "
                "(e.g. dnspython), which is not a project dependency here — "
                "skipped rather than approximated. stdlib socket only resolves "
                "A/CNAME via getaddrinfo/gethostbyname."
            )
        }
        return out


@register_probe
class OnmicrosoftTenantDerivation(M365Probe):
    """Guesses the tenant's *.onmicrosoft.com name and confirms it.

    Microsoft derives the default onmicrosoft.com name from the org name at
    tenant creation, typically the vanity domain's first label with
    non-alphanumeric characters stripped — a well-known guess-and-check OSINT
    technique. This re-runs the same public
    `/v2.0/.well-known/openid-configuration` check TenantOpenIdConfig uses,
    just pointed at the derived name instead of the vanity domain, which is
    useful when the SOAP-based TenantFederationDomains call is blocked or the
    vanity domain itself isn't Entra-verified yet. A caller that already knows
    the real onmicrosoft name (e.g. from TenantFederationDomains) can skip the
    guess via params['onmicrosoft_tenant']. Same endpoint, same tier as
    TenantOpenIdConfig: PASSIVE.
    """

    name = "m365-onmicrosoft-derive"
    blast_radius = BlastRadius.PASSIVE

    def collect(self, domain: str, params: dict, http: httpx.Client) -> dict[str, Any]:
        label = re.sub(r"[^a-z0-9]", "", domain.split(".")[0].lower())
        candidate = params.get("onmicrosoft_tenant") or f"{label}.onmicrosoft.com"
        out: dict[str, Any] = {"domain": domain, "candidate": candidate}
        url = f"{LOGIN}/{candidate}/v2.0/.well-known/openid-configuration"
        try:
            r = http.get(url)
            out["status_code"] = r.status_code
            out["candidate_exists"] = r.status_code == 200
            if r.status_code == 200:
                issuer = r.json().get("issuer", "")
                parts = [p for p in issuer.split("/") if p]
                out["candidate_tenant_id"] = parts[-2] if len(parts) >= 2 else None
        except httpx.HTTPError as e:
            out["error"] = str(e)
        return out


@register_probe
class SharePointTenantExistence(M365Probe):
    """Does a SharePoint Online / OneDrive tenant exist for this org?

    Every M365 tenant is provisioned `<tenant>.sharepoint.com` (SharePoint)
    and `<tenant>-my.sharepoint.com` (OneDrive/OneDrive redirection) by
    default. A HEAD to either gets a real HTTP response (redirect to sign-in,
    403, etc.) if the tenant exists, or a DNS/TLS failure if it doesn't — a
    pure existence signal; no content is fetched or parsed. `<tenant>` is the
    same derived onmicrosoft label as OnmicrosoftTenantDerivation (reused via
    params['onmicrosoft_tenant'] when a caller already resolved it). HEAD
    only, no auth: PASSIVE.
    """

    name = "m365-sharepoint-tenant"
    blast_radius = BlastRadius.PASSIVE

    def collect(self, domain: str, params: dict, http: httpx.Client) -> dict[str, Any]:
        onms = params.get("onmicrosoft_tenant", "")
        label = onms.split(".")[0] if onms else re.sub(r"[^a-z0-9]", "", domain.split(".")[0].lower())
        out: dict[str, Any] = {"domain": domain, "tenant_label": label, "sites": {}}
        targets = (("sharepoint", f"{label}.sharepoint.com"), ("onedrive", f"{label}-my.sharepoint.com"))
        for i, (kind, host) in enumerate(targets):
            url = f"https://{host}/"
            rec: dict[str, Any] = {"url": url}
            try:
                r = http.head(url)
                rec["status_code"] = r.status_code
                rec["exists"] = r.status_code < 500  # any real HTTP response means DNS+TLS resolved
            except httpx.HTTPError as e:
                rec["exists"] = False
                rec["error"] = str(e)
            out["sites"][kind] = rec
            if i < len(targets) - 1:
                polite_sleep()
        return out


@register_probe
class AutodiscoverV2(M365Probe):
    """Exchange Online routing fingerprint via the Autodiscover v2 JSON API.

    The v2 JSON endpoint is unauthenticated and answers for any syntactically
    valid UPN without first validating the mailbox exists — like UserRealm, we
    send the benign non-account PROBE_USER, so this stays a tenant-level
    signal (is mail for this domain routed through EXO, which protocol does
    Autodiscover advertise) rather than a check on any real person's mailbox.
    PASSIVE.
    """

    name = "m365-autodiscover-v2"
    blast_radius = BlastRadius.PASSIVE

    def collect(self, domain: str, params: dict, http: httpx.Client) -> dict[str, Any]:
        upn = f"{PROBE_USER}@{domain}"
        url = f"{AUTODISCOVER}/autodiscover/autodiscover.json/v1.0/{upn}?Protocol=Autodiscoverv1"
        out: dict[str, Any] = {"domain": domain, "probe_upn": upn, "url": url}
        try:
            r = http.get(url)
            out["status_code"] = r.status_code
            try:
                body = r.json()
            except ValueError:
                body = None
            if body is not None:
                if r.status_code == 200:
                    out["protocol"] = body.get("Protocol")
                    out["url_result"] = body.get("Url")
                else:
                    err = body.get("Error") if isinstance(body, dict) else body
                    out["error_body"] = err
        except httpx.HTTPError as e:
            out["error"] = str(e)
        return out


@register_probe
class TeamsSkypeFederation(M365Probe):
    """Skype for Business Online / Teams federation discovery for the domain.

    The Lync/SfB Online "webdir" autodiscover service resolves a domain to its
    tenant's federation endpoints with no credential at all — it exists so
    federated-chat clients on other tenants know where to route a
    conversation. A structured response confirms the domain is homed on
    Teams/SfB Online and surfaces the tenant's discovery/external-access
    endpoints; a failure just means it isn't (or federation is disabled).
    Unauthenticated GET only: PASSIVE.
    """

    name = "m365-teams-skype"
    blast_radius = BlastRadius.PASSIVE

    def collect(self, domain: str, params: dict, http: httpx.Client) -> dict[str, Any]:
        url = f"https://webdir.online.lync.com/Autodiscover/AutodiscoverService.svc/root?originalDomain={domain}"
        out: dict[str, Any] = {"domain": domain, "url": url}
        try:
            r = http.get(url, headers={"Accept": "application/json"})
            out["status_code"] = r.status_code
            if r.status_code == 200:
                try:
                    body = r.json()
                except ValueError:
                    out["raw_snippet"] = r.text[:500]
                else:
                    links = body.get("_links", {}) if isinstance(body, dict) else {}
                    out["links"] = {
                        k: v.get("href") for k, v in links.items() if isinstance(v, dict) and v.get("href")
                    }
                    out["teams_or_sfb_present"] = bool(out["links"])
        except httpx.HTTPError as e:
            out["error"] = str(e)
        return out
