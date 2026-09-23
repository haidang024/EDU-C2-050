"""sanitization_service — strip sensitive patterns from retrieved policy text.

Applied before any content is written to state or passed to an LLM (S-2 boundary).
"""

from __future__ import annotations

import re
from typing import List


def sanitize(text: str, patterns: List[str]) -> str:
    """Return text with lines matching any sensitive pattern replaced by a placeholder.

    Each pattern is matched against the full line (re.search). Matching lines are
    replaced entirely rather than masked inline to avoid partial leakage.
    """
    if not text or not patterns:
        return text

    compiled = [re.compile(p) for p in patterns]
    output_lines: List[str] = []
    for line in text.splitlines():
        if any(pat.search(line) for pat in compiled):
            output_lines.append("[REDACTED — sensitive pattern]")
        else:
            output_lines.append(line)
    return "\n".join(output_lines)


def contains_credentials(text: str, patterns: List[str]) -> bool:
    """Return True if the text contains any credential/secret pattern."""
    compiled = [re.compile(p) for p in patterns]
    return any(pat.search(text) for pat in compiled)


def scan_for_sensitive(obj: object, patterns: List[str]) -> List[str]:
    """Recursively scan a dict/list/str for sensitive patterns.

    Returns a list of field paths where matches were found.
    """
    compiled = [re.compile(p) for p in patterns]
    findings: List[str] = []
    _scan(obj, compiled, "", findings)
    return findings


def _scan(obj: object, compiled: list, path: str, findings: List[str]) -> None:
    if isinstance(obj, str):
        if any(pat.search(obj) for pat in compiled):
            findings.append(path or "<root>")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _scan(v, compiled, f"{path}.{k}" if path else k, findings)
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _scan(v, compiled, f"{path}[{i}]", findings)
