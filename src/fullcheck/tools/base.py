from __future__ import annotations
import shutil
import subprocess
from dataclasses import dataclass
from typing import Sequence
from ..action import Action, BlastRadius
from ..dispatcher import Dispatcher
from ..evidence import Evidence


@dataclass
class ToolResult:
    action: Action
    stdout: bytes
    stderr: bytes
    exit_code: int
    artifact_path: str


class Tool:
    """Base wrapper. Subclasses set name, binary, blast_radius, build_cmd()."""

    name: str = ""
    binary: str = ""
    blast_radius: BlastRadius = BlastRadius.PASSIVE

    def build_cmd(self, target: str, params: dict) -> Sequence[str]:
        raise NotImplementedError

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def run(
        self,
        target: str,
        engagement: str,
        dispatcher: Dispatcher,
        evidence: Evidence,
        params: dict | None = None,
        timeout: int = 900,
    ) -> ToolResult:
        params = params or {}
        action = Action(
            tool=self.name,
            target=target,
            params=params,
            blast_radius=self.blast_radius,
            reason=params.get("_reason", ""),
            engagement=engagement,
        )
        dispatcher.check(action)  # raises if not allowed
        if not self.available():
            raise RuntimeError(f"binary not found on PATH: {self.binary}")
        cmd = list(self.build_cmd(target, params))
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout, check=False
        )
        artifact = evidence.record(
            action=action,
            stdout=proc.stdout,
            stderr=proc.stderr,
            exit_code=proc.returncode,
            artifact_name=target.replace("/", "_").replace(":", "_"),
        )
        return ToolResult(
            action=action,
            stdout=proc.stdout,
            stderr=proc.stderr,
            exit_code=proc.returncode,
            artifact_path=str(artifact),
        )
