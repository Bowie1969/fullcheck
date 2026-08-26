from __future__ import annotations
from typing import Sequence
from ..action import BlastRadius
from .base import Tool


class Subfinder(Tool):
    name = "subfinder"
    binary = "subfinder"
    blast_radius = BlastRadius.PASSIVE

    def build_cmd(self, target: str, params: dict) -> Sequence[str]:
        return ["subfinder", "-d", target, "-silent", "-json"]


class Dnsx(Tool):
    name = "dnsx"
    binary = "dnsx"
    blast_radius = BlastRadius.PASSIVE

    def build_cmd(self, target: str, params: dict) -> Sequence[str]:
        # target is a domain; resolve A/AAAA/CNAME/MX/TXT
        return [
            "dnsx", "-d", target, "-silent", "-json",
            "-a", "-aaaa", "-cname", "-mx", "-txt", "-resp",
        ]


class Httpx(Tool):
    name = "httpx"
    binary = "httpx"
    blast_radius = BlastRadius.PROBE

    def build_cmd(self, target: str, params: dict) -> Sequence[str]:
        return [
            "httpx", "-u", target, "-silent", "-json",
            "-status-code", "-title", "-tech-detect", "-tls-grab",
            "-web-server", "-follow-redirects",
        ]


class Naabu(Tool):
    name = "naabu"
    binary = "naabu"
    blast_radius = BlastRadius.PROBE

    def build_cmd(self, target: str, params: dict) -> Sequence[str]:
        top = str(params.get("top_ports", 1000))
        return ["naabu", "-host", target, "-silent", "-json", "-top-ports", top]


class Katana(Tool):
    name = "katana"
    binary = "katana"
    blast_radius = BlastRadius.PROBE

    def build_cmd(self, target: str, params: dict) -> Sequence[str]:
        # passive crawl only in v0.1
        return ["katana", "-u", target, "-silent", "-json", "-passive", "-jc"]


class NucleiScan(Tool):
    name = "nuclei"
    binary = "nuclei"
    blast_radius = BlastRadius.SCAN  # gated by engagement ceiling

    def build_cmd(self, target: str, params: dict) -> Sequence[str]:
        tags = params.get(
            "tags", "cve,misconfig,default-login,exposure,exposed-panel,tokens"
        )
        sev = params.get("severity", "low,medium,high,critical")
        return [
            "nuclei", "-u", target, "-silent", "-json",
            "-tags", tags, "-severity", sev, "-rate-limit", "50",
        ]


class Gowitness(Tool):
    name = "gowitness"
    binary = "gowitness"
    blast_radius = BlastRadius.PROBE

    def build_cmd(self, target: str, params: dict) -> Sequence[str]:
        outdir = params.get("_screenshot_dir", "screenshots")
        return ["gowitness", "single", "--screenshot-path", outdir, target]


class Trufflehog(Tool):
    name = "trufflehog"
    binary = "trufflehog"
    blast_radius = BlastRadius.PASSIVE

    def build_cmd(self, target: str, params: dict) -> Sequence[str]:
        # target is a github org/user url
        return ["trufflehog", "github", "--org", target, "--json"]


class Dnstwist(Tool):
    name = "dnstwist"
    binary = "dnstwist"
    blast_radius = BlastRadius.PASSIVE

    def build_cmd(self, target: str, params: dict) -> Sequence[str]:
        return ["dnstwist", "--format", "json", "--registered", target]


# Registry used by the runner. Order = execution order.
RECON_PIPELINE = [
    Subfinder(),
    Dnsx(),
    Httpx(),
    Naabu(),
    Katana(),
    NucleiScan(),
    Dnstwist(),
]
