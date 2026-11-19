"""Rule definitions, severity levels, and Finding dataclass."""

from dataclasses import dataclass, asdict
from typing import Dict, Any

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


@dataclass
class Finding:
    rule_id: str
    severity: str
    file: str
    line: int
    message: str
    remediation: str
    target: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


RULES: Dict[str, Dict[str, str]] = {
    "DF001": {
        "severity": "high",
        "title": "Unpinned base image (:latest or untagged)",
        "remediation": "Pin base image to an explicit version tag and/or SHA256 digest (e.g. python:3.12-slim@sha256:...).",
    },
    "DF002": {
        "severity": "high",
        "title": "Container runs as root (missing USER instruction)",
        "remediation": "Add a non-root USER instruction (e.g. USER 10001:10001 or USER appuser).",
    },
    "DF003": {
        "severity": "critical",
        "title": "Remote script piped directly to shell (curl/wget | sh/bash)",
        "remediation": "Download artifacts, verify SHA256 checksums/signatures, and execute explicitly.",
    },
    "DF004": {
        "severity": "medium",
        "title": "ADD instruction used with remote URL",
        "remediation": "Use curl/wget with checksum verification in RUN, or COPY for local files.",
    },
    "DF005": {
        "severity": "critical",
        "title": "Hardcoded secret or credential in ENV/ARG",
        "remediation": "Pass secrets at runtime via Docker secrets, mounted files, or secret managers.",
    },
    "DF006": {
        "severity": "low",
        "title": "Missing HEALTHCHECK instruction",
        "remediation": "Define a HEALTHCHECK instruction so orchestrators can detect unhealthy containers.",
    },
    "DC001": {
        "severity": "critical",
        "title": "Service runs in privileged mode (privileged: true)",
        "remediation": "Remove privileged: true and grant only minimal Linux capabilities via cap_add.",
    },
    "DC002": {
        "severity": "high",
        "title": "Service uses host network namespace (network_mode: host)",
        "remediation": "Use isolated bridge networks and publish only required ports.",
    },
    "DC003": {
        "severity": "critical",
        "title": "Docker socket mounted inside container (/var/run/docker.sock)",
        "remediation": "Avoid mounting docker.sock; use a restricted socket proxy or rootless API if required.",
    },
    "DC004": {
        "severity": "high",
        "title": "Database port exposed on 0.0.0.0",
        "remediation": "Bind database ports to 127.0.0.1 (e.g. 127.0.0.1:5432:5432) or keep them internal.",
    },
    "DC005": {
        "severity": "medium",
        "title": "Missing read_only: true root filesystem",
        "remediation": "Set read_only: true and mount explicit tmpfs/volumes for writable paths.",
    },
    "DC006": {
        "severity": "medium",
        "title": "Missing memory limit (mem_limit / deploy.resources.limits.memory)",
        "remediation": "Configure mem_limit or deploy.resources.limits.memory to prevent OOM DoS.",
    },
    "DC007": {
        "severity": "high",
        "title": "Unpinned service image (:latest or untagged)",
        "remediation": "Pin service image to an explicit version tag or SHA256 digest.",
    },
    "DC008": {
        "severity": "critical",
        "title": "Hardcoded secret in Compose environment",
        "remediation": "Use external .env files, Docker secrets, or runtime secret injection.",
    },
}
