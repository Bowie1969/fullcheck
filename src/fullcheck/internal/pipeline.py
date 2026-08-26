"""The discovery/enumeration pipeline the internal swarm fans out.

Passed to the reused `orchestrator.run_swarm(..., pipeline=...)`. Every tool
here is PROBE or SCAN tier — the auto-fire discovery surface. Exploitation is
never part of this pipeline; it goes through the catalog + autonomy router +
ApprovalGate. Order is execution order per target.
"""

from __future__ import annotations

from .tools.discovery import Enum4linux, NetexecSmb, NmapPing, NmapServices, SmbMap
from .tools.enum import LdapAnon, NucleiInternal, SnmpCheck

INTERNAL_DISCOVERY_PIPELINE = [
    NmapPing(),
    NmapServices(),
    NetexecSmb(),
    Enum4linux(),
    SmbMap(),
    LdapAnon(),
    SnmpCheck(),
    NucleiInternal(),
]
