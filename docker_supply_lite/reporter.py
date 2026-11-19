"""Output formatters (JSON, Markdown, Text) for lint findings."""

import json
from typing import List, Dict
from .rules import Finding, SEVERITY_ORDER


def summarize(findings: List[Finding]) -> Dict[str, int]:
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    counts["total"] = len(findings)
    return counts


def format_json(findings: List[Finding]) -> str:
    payload = {
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def format_markdown(findings: List[Finding]) -> str:
    summary = summarize(findings)
    lines = [
        "# Docker & Compose Supply-Chain Audit Report",
        "",
        f"- **Total findings:** {summary['total']}",
        f"- **Critical:** {summary['critical']} | **High:** {summary['high']} | **Medium:** {summary['medium']} | **Low:** {summary['low']}",
        "",
    ]
    if not findings:
        lines.append("No security or supply-chain issues detected.")
        return "\n".join(lines)

    lines.extend(
        [
            "| Rule | Severity | File:Line | Message |",
            "|------|----------|-----------|---------|",
        ]
    )
    for f in findings:
        lines.append(f"| `{f.rule_id}` | {f.severity.upper()} | `{f.file}:{f.line}` | {f.message} |")
    return "\n".join(lines)


def format_text(findings: List[Finding]) -> str:
    if not findings:
        return "PASS: No security or supply-chain issues detected."
    lines = []
    for f in findings:
        lines.append(f"[{f.severity.upper()}] {f.rule_id} {f.file}:{f.line} - {f.message}")
    summary = summarize(findings)
    lines.append(
        f"\nSummary: {summary['total']} findings "
        f"(critical={summary['critical']}, high={summary['high']}, medium={summary['medium']}, low={summary['low']})"
    )
    return "\n".join(lines)
