"""Offline docker-compose.yml security & supply-chain linter (pure stdlib)."""

import re
from typing import Dict, List, Any
from .rules import Finding, RULES
from .dockerfile_linter import _is_unpinned_image, SECRET_KEY_RE

DB_PORTS = {"5432", "3306", "27017", "6379", "9200", "5984", "1433", "1521", "9042"}


def _parse_compose_services(content: str) -> Dict[str, Dict[str, Any]]:
    """Lightweight indentation-based YAML parser for docker-compose services."""
    services: Dict[str, Dict[str, Any]] = {}
    lines = content.splitlines()
    in_services = False
    services_indent = -1
    current_svc = None
    svc_indent = -1
    current_key = None
    key_indent = -1

    for idx, raw in enumerate(lines, start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()

        if not in_services:
            if stripped == "services:":
                in_services = True
                services_indent = indent
            continue

        # Left services block
        if indent <= services_indent and not stripped.startswith("-"):
            break

        # Service name level
        if (svc_indent == -1 or indent == svc_indent) and stripped.endswith(":") and not stripped.startswith("-"):
            svc_indent = indent
            current_svc = stripped[:-1].strip()
            services[current_svc] = {"_line": idx, "_raw": []}
            current_key = None
            continue

        if current_svc is None:
            continue

        services[current_svc]["_raw"].append((idx, indent, stripped))

        # Top-level key inside service
        if ":" in stripped and not stripped.startswith("-"):
            k, v = stripped.split(":", 1)
            k = k.strip()
            v = v.strip()
            if key_indent == -1 or indent <= key_indent:
                key_indent = indent
                current_key = k
                services[current_svc][k] = {"line": idx, "value": v, "items": []}
            else:
                # Nested key (e.g. deploy.resources.limits.memory)
                services[current_svc].setdefault("_nested", []).append((idx, k, v))
        elif stripped.startswith("-") and current_key:
            item = stripped[1:].strip().strip('"').strip("'")
            services[current_svc][current_key]["items"].append((idx, item))

    return services


def lint_compose(content: str, filename: str = "docker-compose.yml") -> List[Finding]:
    findings: List[Finding] = []
    services = _parse_compose_services(content)

    for svc_name, data in services.items():
        svc_line = data.get("_line", 1)

        # DC007: unpinned image
        if "image" in data and data["image"]["value"]:
            img = data["image"]["value"]
            if _is_unpinned_image(img):
                findings.append(
                    Finding(
                        rule_id="DC007",
                        severity=RULES["DC007"]["severity"],
                        file=filename,
                        line=data["image"]["line"],
                        message=f"Service '{svc_name}' uses unpinned image '{img}'.",
                        remediation=RULES["DC007"]["remediation"],
                        target=svc_name,
                    )
                )

        # DC001: privileged: true
        if "privileged" in data and data["privileged"]["value"].lower() == "true":
            findings.append(
                Finding(
                    rule_id="DC001",
                    severity=RULES["DC001"]["severity"],
                    file=filename,
                    line=data["privileged"]["line"],
                    message=f"Service '{svc_name}' runs with privileged: true.",
                    remediation=RULES["DC001"]["remediation"],
                    target=svc_name,
                )
            )

        # DC002: network_mode: host
        if "network_mode" in data and data["network_mode"]["value"].strip('"').strip("'").lower() == "host":
            findings.append(
                Finding(
                    rule_id="DC002",
                    severity=RULES["DC002"]["severity"],
                    file=filename,
                    line=data["network_mode"]["line"],
                    message=f"Service '{svc_name}' uses network_mode: host.",
                    remediation=RULES["DC002"]["remediation"],
                    target=svc_name,
                )
            )

        # DC003: /var/run/docker.sock
        if "volumes" in data:
            for ln, vol in data["volumes"]["items"]:
                if "/var/run/docker.sock" in vol:
                    findings.append(
                        Finding(
                            rule_id="DC003",
                            severity=RULES["DC003"]["severity"],
                            file=filename,
                            line=ln,
                            message=f"Service '{svc_name}' mounts Docker socket ({vol}).",
                            remediation=RULES["DC003"]["remediation"],
                            target=svc_name,
                        )
                    )

        # DC004: 0.0.0.0 exposed database ports
        if "ports" in data:
            for ln, port_spec in data["ports"]["items"]:
                # Examples: "0.0.0.0:5432:5432", "5432:5432"
                parts = port_spec.split(":")
                is_wildcard = False
                container_port = ""
                if len(parts) == 3 and parts[0] in {"0.0.0.0", "::"}:
                    is_wildcard = True
                    container_port = parts[2].split("/")[0]
                elif len(parts) == 2:
                    is_wildcard = True
                    container_port = parts[1].split("/")[0]
                if is_wildcard and container_port in DB_PORTS:
                    findings.append(
                        Finding(
                            rule_id="DC004",
                            severity=RULES["DC004"]["severity"],
                            file=filename,
                            line=ln,
                            message=f"Service '{svc_name}' exposes database port '{port_spec}' on 0.0.0.0.",
                            remediation=RULES["DC004"]["remediation"],
                            target=svc_name,
                        )
                    )

        # DC008: hardcoded secrets in environment
        if "environment" in data:
            for ln, item in data["environment"]["items"]:
                if "=" in item:
                    k, v = item.split("=", 1)
                    if SECRET_KEY_RE.search(k) and v.strip() and not v.strip().startswith("$"):
                        findings.append(
                            Finding(
                                rule_id="DC008",
                                severity=RULES["DC008"]["severity"],
                                file=filename,
                                line=ln,
                                message=f"Service '{svc_name}' has hardcoded secret '{k}' in environment.",
                                remediation=RULES["DC008"]["remediation"],
                                target=svc_name,
                            )
                        )
            for ln, k, v in data.get("_nested", []):
                if SECRET_KEY_RE.search(k) and v.strip() and not v.strip().startswith("$"):
                    findings.append(
                        Finding(
                            rule_id="DC008",
                            severity=RULES["DC008"]["severity"],
                            file=filename,
                            line=ln,
                            message=f"Service '{svc_name}' has hardcoded secret '{k}' in environment.",
                            remediation=RULES["DC008"]["remediation"],
                            target=svc_name,
                        )
                    )

        # DC005: missing read_only: true
        read_only_val = data.get("read_only", {}).get("value", "").lower()
        if read_only_val != "true":
            findings.append(
                Finding(
                    rule_id="DC005",
                    severity=RULES["DC005"]["severity"],
                    file=filename,
                    line=svc_line,
                    message=f"Service '{svc_name}' is missing read_only: true.",
                    remediation=RULES["DC005"]["remediation"],
                    target=svc_name,
                )
            )

        # DC006: missing mem_limit or deploy.resources.limits.memory
        has_mem_limit = "mem_limit" in data or any(
            k == "memory" for _, k, _ in data.get("_nested", [])
        )
        if not has_mem_limit:
            findings.append(
                Finding(
                    rule_id="DC006",
                    severity=RULES["DC006"]["severity"],
                    file=filename,
                    line=svc_line,
                    message=f"Service '{svc_name}' is missing mem_limit / memory resource limit.",
                    remediation=RULES["DC006"]["remediation"],
                    target=svc_name,
                )
            )

    return findings
