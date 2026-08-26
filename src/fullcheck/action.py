from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class BlastRadius(str, Enum):
    PASSIVE = "passive"
    PROBE = "probe"
    SCAN = "scan"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"


_ORDER = [
    BlastRadius.PASSIVE,
    BlastRadius.PROBE,
    BlastRadius.SCAN,
    BlastRadius.EXPLOIT,
    BlastRadius.POST_EXPLOIT,
]


def exceeds(a: BlastRadius, ceiling: BlastRadius) -> bool:
    return _ORDER.index(a) > _ORDER.index(ceiling)


@dataclass
class Action:
    tool: str
    target: str
    params: dict[str, Any] = field(default_factory=dict)
    blast_radius: BlastRadius = BlastRadius.PASSIVE
    reason: str = ""
    engagement: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["blast_radius"] = self.blast_radius.value
        return d
