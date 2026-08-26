"""Directory / service enumeration and internal vuln scanning.

LDAP anonymous bind, SNMP public-community read, and Nuclei against internal web
services. Nuclei is SCAN-tier (a shade heavier than PROBE), so a zone capped at
`probe` in scope.yaml will skip it while still allowing host/port/share enum.
"""

from __future__ import annotations

from typing import Sequence

from ...action import BlastRadius
from ...tools.base import Tool


class LdapAnon(Tool):
    name = "nxc-ldap"
    binary = "nxc"
    blast_radius = BlastRadius.PROBE

    def build_cmd(self, target: str, params: dict) -> Sequence[str]:
        # anonymous bind; --users pulls the domain user list where allowed
        return ["nxc", "ldap", target, "-u", "", "-p", "", "--users"]


class SnmpCheck(Tool):
    name = "snmp-check"
    binary = "snmp-check"
    blast_radius = BlastRadius.PROBE

    def build_cmd(self, target: str, params: dict) -> Sequence[str]:
        community = params.get("community", "public")
        return ["snmp-check", "-c", community, target]


class NucleiInternal(Tool):
    name = "nuclei-internal"
    binary = "nuclei"
    blast_radius = BlastRadius.SCAN  # gated by engagement/zone ceiling

    def build_cmd(self, target: str, params: dict) -> Sequence[str]:
        sev = params.get("severity", "medium,high,critical")
        tags = params.get("tags", "cve,misconfig,default-login,exposure,network")
        return [
            "nuclei", "-u", target, "-silent", "-json",
            "-severity", sev, "-tags", tags, "-rate-limit", "50",
        ]
