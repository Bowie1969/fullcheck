"""Discovery / enumeration tools — PROBE tier (internally, "discovery").

These are what the swarm fans out. They assert nothing destructive: host
discovery, port/service scanning, and unauthenticated (null-session / anonymous)
share, user and OS enumeration. All go through the Dispatcher like everything
else, so a target outside scope — or inside a zone capped below PROBE — is
skipped, not scanned.

Targets may be a single host or a CIDR; CIDR-aware binaries (nmap, nxc) take a
range directly. `params` may carry `user`/`password` to switch null-session
enumeration to authenticated once a valid credential has been recovered.
"""

from __future__ import annotations

from typing import Sequence

from ...action import BlastRadius
from ...tools.base import Tool


class NmapPing(Tool):
    """Layer-2/3 host discovery (ARP on-LAN, ping otherwise). No port contact."""

    name = "nmap-ping"
    binary = "nmap"
    blast_radius = BlastRadius.PROBE

    def build_cmd(self, target: str, params: dict) -> Sequence[str]:
        return ["nmap", "-sn", "-n", "-oG", "-", target]


class NmapServices(Tool):
    """TCP SYN + service/version scan of the top ports (drop box runs as root)."""

    name = "nmap-services"
    binary = "nmap"
    blast_radius = BlastRadius.PROBE

    def build_cmd(self, target: str, params: dict) -> Sequence[str]:
        top = str(params.get("top_ports", 1000))
        return ["nmap", "-Pn", "-sS", "-sV", "-n", "--top-ports", top, "-oX", "-", target]


class NetexecSmb(Tool):
    """NetExec SMB: OS, signing, null-session shares/users. Authenticates only
    if a recovered credential is supplied in params."""

    name = "nxc-smb"
    binary = "nxc"
    blast_radius = BlastRadius.PROBE

    def build_cmd(self, target: str, params: dict) -> Sequence[str]:
        user = params.get("user", "")
        password = params.get("password", "")
        return ["nxc", "smb", target, "-u", user, "-p", password, "--shares", "--users"]


class Enum4linux(Tool):
    name = "enum4linux-ng"
    binary = "enum4linux-ng"
    blast_radius = BlastRadius.PROBE

    def build_cmd(self, target: str, params: dict) -> Sequence[str]:
        return ["enum4linux-ng", "-A", target]


class SmbMap(Tool):
    name = "smbmap"
    binary = "smbmap"
    blast_radius = BlastRadius.PROBE

    def build_cmd(self, target: str, params: dict) -> Sequence[str]:
        user = params.get("user", "") or ""
        password = params.get("password", "") or ""
        return ["smbmap", "-H", target, "-u", user, "-p", password]
