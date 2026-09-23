"""PolicyRevisionRetrievalNode — Step 2 policy source retrieval and diff.

Inner domain node (DomainWorkflowGraph, ANONYMOUS). Retrieves each declared policy
source, computes a diff against its baseline, sanitizes changed sections before
writing to state, and fails hard if any source is unreachable (no partial briefing).
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, List

from framework.errors import SecurityViolationError
from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.services import sanitization_service
from src.services import source_retrieval_service
from src.services.runtime_config import load_config


class PolicyRevisionRetrievalNode(FunctionNode):
    """Retrieve policy sources, diff vs baseline, and sanitize content."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    # ── S-2 input gate ────────────────────────────────────────────────────
    def _extra_security_gate_input(self, state: dict) -> dict:
        """Scan validated_sources for PII/case-reference patterns before retrieval."""
        config = load_config()
        patterns = config.get("source_sanitization_patterns", [])
        sources = state.get("validated_sources", [])
        import json

        sources_str = json.dumps(sources, ensure_ascii=False)
        findings = sanitization_service.scan_for_sensitive(sources_str, patterns)
        if findings:
            raise SecurityViolationError(
                "S-2: sensitive patterns detected in source config — " f"paths: {', '.join(findings[:5])}"
            )
        return state

    # ── execute (Step 2 logic) ────────────────────────────────────────────
    def execute(self, state: dict) -> dict:
        config = load_config()
        patterns = config.get("source_sanitization_patterns", [])
        validated_sources: List[Dict[str, Any]] = state.get("validated_sources", [])

        ctx = InvocationContext.from_state(state)
        try:
            credential = ctx.secrets.require(config["source_connector_secret_key"])
        except Exception:  # noqa: BLE001
            credential = ""

        source_results: List[Dict[str, Any]] = []
        baseline_age_warning = False
        warnings: List[str] = state.get("review_warnings", []) or []
        error_log: List[str] = state.get("error_log", []) or []

        for src in validated_sources:
            url = src.get("url", "")
            format_hint = src.get("format_hint", "text")
            baseline_ref = src.get("baseline_ref", "")

            try:
                retrieved = source_retrieval_service.retrieve(
                    url=url,
                    format_hint=format_hint,
                    baseline_ref=baseline_ref,
                    credential=credential,
                )
            except source_retrieval_service.SourceRetrievalError as exc:
                # Any failure → hard stop; no partial briefing.
                emit_trace_event(
                    "PolicyRevisionRetrievalNode_source_error",
                    {"url": url, "error": str(exc)},
                    state,
                )
                error_log.append(f"PolicyRevisionRetrievalNode: source unreachable: {url}: {exc}")
                return {
                    "source_results": [],
                    "retrieval_complete": False,
                    "baseline_age_warning": False,
                    "review_warnings": warnings,
                    "error_log": error_log,
                    "status": AgentStatus.ERROR.value,
                }

            sections = retrieved.get("sections", [])
            version = retrieved.get("version", "")
            citations = retrieved.get("citations", [])

            # Diff vs baseline.
            changed = source_retrieval_service.diff_against_baseline(sections, baseline_ref)

            # Sanitize changed sections before writing to state.
            sanitized_sections: List[Dict[str, Any]] = []
            for ch in changed:
                raw_text = ch.get("changed_text", "")
                sanitized_text = sanitization_service.sanitize(raw_text, patterns)
                sanitized_sections.append(
                    {
                        "id": ch["id"],
                        "heading": ch.get("heading", ""),
                        "changed_text": sanitized_text,
                        "baseline_ref": baseline_ref,
                        "diff_summary": ch.get("diff_summary", ""),
                        "source_url": url,
                    }
                )

            content_hash = source_retrieval_service.compute_content_hash(sections)

            emit_trace_event(
                "PolicyRevisionRetrievalNode_source_retrieved",
                {
                    "url": url,
                    "version": version,
                    "changed_section_count": len(sanitized_sections),
                    "content_hash": content_hash,
                },
                state,
            )

            source_results.append(
                {
                    "url": url,
                    "format": format_hint,
                    "status": "ok",
                    "version": version,
                    "content_hash": content_hash,
                    "sanitized_sections": sanitized_sections,
                    "citations": citations,
                    "error_detail": None,
                }
            )

        return {
            "source_results": source_results,
            "retrieval_complete": True,
            "baseline_age_warning": baseline_age_warning,
            "review_warnings": warnings,
            "error_log": error_log,
            "status": AgentStatus.SUCCESS.value,
        }
