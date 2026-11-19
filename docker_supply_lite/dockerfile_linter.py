"""Offline Dockerfile security & supply-chain linter."""

import re
from typing import List, Tuple
from .rules import Finding, RULES

SECRET_KEY_RE = re.compile(
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|aws_secret|db_pass)",
    re.IGNORECASE,
)
PIPE_TO_SHELL_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|ash|dash)\b",
    re.IGNORECASE,
)
REMOTE_URL_RE = re.compile(r"^(?:https?|ftp)://", re.IGNORECASE)


def _join_continuations(raw_lines: List[str]) -> List[Tuple[int, str]]:
    """Join backslash-continued Dockerfile lines while preserving starting line numbers."""
    joined: List[Tuple[int, str]] = []
    buf = ""
    start_ln = 1
    for idx, raw in enumerate(raw_lines, start=1):
        stripped = raw.rstrip("\r\n")
        if not buf:
            if not stripped.strip() or stripped.lstrip().startswith("#"):
                continue
            start_ln = idx
        if stripped.endswith("\\"):
            buf += stripped[:-1].rstrip() + " "
        else:
            buf += stripped
            joined.append((start_ln, buf.strip()))
            buf = ""
    if buf:
        joined.append((start_ln, buf.strip()))
    return joined


def _is_unpinned_image(image_ref: str) -> bool:
    ref = image_ref.strip().strip('"').strip("'")
    if not ref or ref.lower() == "scratch":
        return False
    if ref.startswith("$"):
        return False
    if "@sha256:" in ref:
        return False
    # Handle registry:port/repo:tag
    last_slash = ref.rfind("/")
    after_slash = ref[last_slash + 1 :]
    if ":" not in after_slash:
        return True
    tag = after_slash.split(":", 1)[1].strip()
    return tag == "" or tag.lower() == "latest"


def _is_placeholder(val: str) -> bool:
    v = val.strip().strip('"').strip("'")
    if not v:
        return True
    if v.startswith("$"):
        return True
    if v.lower() in {"changeme", "placeholder", "example", "<secret>", "none", "null"}:
        return False  # Still risky if someone leaves changeme, but let's flag non-empty literals
    return False


def lint_dockerfile(content: str, filename: str = "Dockerfile") -> List[Finding]:
    findings: List[Finding] = []
    instructions = _join_continuations(content.splitlines())

    has_user = False
    has_healthcheck = False
    last_user_is_root = False

    for ln, line in instructions:
        parts = line.split(None, 1)
        if not parts:
            continue
        cmd = parts[0].upper()
        rest = parts[1].strip() if len(parts) > 1 else ""

        if cmd == "FROM":
            # Strip --platform=... if present
            tokens = rest.split()
            img = ""
            for tok in tokens:
                if not tok.startswith("--"):
                    img = tok
                    break
            if img and _is_unpinned_image(img):
                findings.append(
                    Finding(
                        rule_id="DF001",
                        severity=RULES["DF001"]["severity"],
                        file=filename,
                        line=ln,
                        message=f"Base image '{img}' is unpinned (uses :latest or no tag).",
                        remediation=RULES["DF001"]["remediation"],
                        target=img,
                    )
                )

        elif cmd == "USER":
            has_user = True
            user_val = rest.split(":", 1)[0].strip().lower()
            last_user_is_root = user_val in {"root", "0"}

        elif cmd == "HEALTHCHECK":
            if not rest.upper().startswith("NONE"):
                has_healthcheck = True

        elif cmd == "RUN":
            if PIPE_TO_SHELL_RE.search(rest):
                findings.append(
                    Finding(
                        rule_id="DF003",
                        severity=RULES["DF003"]["severity"],
                        file=filename,
                        line=ln,
                        message="Remote script piped directly into shell (curl/wget | sh/bash).",
                        remediation=RULES["DF003"]["remediation"],
                        target=rest[:80],
                    )
                )

        elif cmd == "ADD":
            tokens = [t for t in rest.split() if not t.startswith("--")]
            if tokens and REMOTE_URL_RE.match(tokens[0]):
                findings.append(
                    Finding(
                        rule_id="DF004",
                        severity=RULES["DF004"]["severity"],
                        file=filename,
                        line=ln,
                        message=f"ADD used with remote URL '{tokens[0]}'.",
                        remediation=RULES["DF004"]["remediation"],
                        target=tokens[0],
                    )
                )

        elif cmd in {"ENV", "ARG"}:
            # Support KEY=VALUE or KEY VALUE
            pairs = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^\s]+)", rest)
            if not pairs and " " in rest and "=" not in rest:
                k, v = rest.split(None, 1)
                pairs = [(k, v)]
            for k, v in pairs:
                if SECRET_KEY_RE.search(k) and not _is_placeholder(v):
                    findings.append(
                        Finding(
                            rule_id="DF005",
                            severity=RULES["DF005"]["severity"],
                            file=filename,
                            line=ln,
                            message=f"Potential hardcoded secret in {cmd} '{k}'.",
                            remediation=RULES["DF005"]["remediation"],
                            target=k,
                        )
                    )

    if instructions:
        if not has_user or last_user_is_root:
            findings.append(
                Finding(
                    rule_id="DF002",
                    severity=RULES["DF002"]["severity"],
                    file=filename,
                    line=1,
                    message="Container runs as root (missing non-root USER instruction).",
                    remediation=RULES["DF002"]["remediation"],
                )
            )
        if not has_healthcheck:
            findings.append(
                Finding(
                    rule_id="DF006",
                    severity=RULES["DF006"]["severity"],
                    file=filename,
                    line=1,
                    message="Missing HEALTHCHECK instruction.",
                    remediation=RULES["DF006"]["remediation"],
                )
            )

    return findings
