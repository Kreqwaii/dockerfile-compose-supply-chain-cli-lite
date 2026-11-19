"""CLI entrypoint for dockerfile-compose-supply-chain-cli-lite."""

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .dockerfile_linter import lint_dockerfile
from .compose_linter import lint_compose
from .reporter import format_json, format_markdown, format_text
from .rules import Finding, SEVERITY_ORDER


def _detect_and_lint(path: str) -> List[Finding]:
    with open(path, "r", encoding="utf-8") as fh:
        content = fh.read()
    name = os.path.basename(path).lower()
    if "compose" in name or name.endswith((".yml", ".yaml")):
        return lint_compose(content, filename=path)
    return lint_dockerfile(content, filename=path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="docker-supply-lite",
        description="Offline security & supply-chain linter for Dockerfile and docker-compose.yml.",
    )
    parser.add_argument("paths", nargs="+", help="Dockerfile(s) or docker-compose.yml file(s) to scan")
    parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="high",
        help="Exit with code 1 if any finding meets or exceeds this severity (default: high)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    all_findings: List[Finding] = []
    for p in args.paths:
        if not os.path.isfile(p):
            print(f"Error: file not found: {p}", file=sys.stderr)
            return 2
        all_findings.extend(_detect_and_lint(p))

    if args.format == "json":
        print(format_json(all_findings))
    elif args.format == "markdown":
        print(format_markdown(all_findings))
    else:
        print(format_text(all_findings))

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in all_findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
