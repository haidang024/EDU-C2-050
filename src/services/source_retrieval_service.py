"""source_retrieval_service — stub retrieve/diff functions for policy sources.

In production these would call real HTTP/storage connectors. Here they return
realistic simulated data so the node logic, security gates, and tests are fully
exercisable without external dependencies.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List


# Unreachable host patterns used by tests to trigger failure paths.
_UNREACHABLE_PATTERNS = [
    re.compile(r"unreachable"),
    re.compile(r"offline"),
    re.compile(r"404"),
]


class SourceRetrievalError(Exception):
    """Raised when a source cannot be reached or parsed."""


def retrieve(
    url: str,
    format_hint: str,
    baseline_ref: str,
    credential: str,
) -> Dict[str, Any]:
    """Retrieve a policy source and return structured content.

    Returns::

        {
            "sections": [{"id": str, "heading": str, "text": str}],
            "version": str,
            "citations": [{"ref": str, "title": str}],
            "error": None | str,
        }

    Raises SourceRetrievalError when the source is unreachable.
    """
    for pattern in _UNREACHABLE_PATTERNS:
        if pattern.search(url):
            raise SourceRetrievalError(f"Source unreachable: {url}")

    # Simulate retrieved content (realistic stub).
    sections = _simulate_sections(url, format_hint)
    version = _derive_version(url)
    citations = _simulate_citations(baseline_ref)

    return {
        "sections": sections,
        "version": version,
        "citations": citations,
        "error": None,
    }


def diff_against_baseline(
    current_sections: List[Dict[str, Any]],
    baseline_ref: str,
) -> List[Dict[str, Any]]:
    """Return sections that differ from the baseline.

    In production this would fetch the baseline version from a document store
    and compare. Here we simulate that some sections have changed.
    """
    changed: List[Dict[str, Any]] = []
    for section in current_sections:
        text = section.get("text", "")
        # Simulate: sections with "updated" or "revised" in text are flagged changed.
        if "updated" in text.lower() or "revised" in text.lower() or len(text) > 80:
            changed.append(
                {
                    "id": section["id"],
                    "heading": section.get("heading", ""),
                    "changed_text": text,
                    "baseline_ref": baseline_ref,
                    "diff_summary": f"Section {section['id']} content changed vs baseline {baseline_ref}",
                }
            )
    return changed


def compute_content_hash(sections: List[Dict[str, Any]]) -> str:
    """Return a stable SHA-256 hash of the section texts."""
    joined = "\n".join(s.get("text", "") for s in sections)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


# ── Private helpers ───────────────────────────────────────────────────────────


def _simulate_sections(url: str, format_hint: str) -> List[Dict[str, Any]]:
    """Return simulated policy sections based on the URL."""
    domain_key = url.split("/")[-1].split(".")[0] if "/" in url else "doc"
    return [
        {
            "id": f"{domain_key}-s1",
            "heading": "Definitions and Scope",
            "text": (
                "This policy has been updated to reflect statutory guidance issued "
                "in September 2024. All staff must complete mandatory safeguarding "
                "training within 30 days of joining."
            ),
        },
        {
            "id": f"{domain_key}-s2",
            "heading": "Reporting Obligations",
            "text": (
                "The Designated Safeguarding Lead (DSL) is responsible for making "
                "referrals to children's social care. This section has been revised "
                "to align with updated multi-agency guidance."
            ),
        },
        {
            "id": f"{domain_key}-s3",
            "heading": "Record Keeping",
            "text": "Records must be stored securely in line with data protection legislation.",
        },
    ]


def _derive_version(url: str) -> str:
    h = hashlib.md5(url.encode()).hexdigest()[:8]  # noqa: S324
    return f"v2025-{h}"


def _simulate_citations(baseline_ref: str) -> List[Dict[str, Any]]:
    return [
        {"ref": "KCSIE-2024", "title": "Keeping Children Safe in Education 2024"},
        {"ref": baseline_ref, "title": f"Baseline: {baseline_ref}"},
    ]
