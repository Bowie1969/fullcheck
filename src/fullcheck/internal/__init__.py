"""FullCheck-Internal — the on-site / internal-network sibling of FullCheck.

Same spine as the external tool (Action, Dispatcher, ApprovalGate, Evidence,
the ≤50-worker swarm) — imported, never forked, so the safety guarantees can't
drift between the two tools. What differs is what the blast-radius tiers *mean*
on the wire, and a structural FLOOR/CEILING impact class on every exploit
technique (see catalog.py) that the autonomy dial cannot lower.

Runtime target: an x86 drop box (Parrot/Kali) placed on the client LAN. Tools
run locally via subprocess, exactly like the external tool on ParrotOS.
"""

__version__ = "0.3.0"
