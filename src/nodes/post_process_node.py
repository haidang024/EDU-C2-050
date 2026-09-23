"""BriefingGenerationNode — Step 4 Markdown briefing generation + S-3 output gate.

Boundary node (outer AgentBaseGraph, INTERNAL). Generates a Markdown briefing from
change findings with a mandatory disclaimer, always sets requires_human_review True,
and runs the S-3 output scan to block any credentials or sensitive content from
reaching the caller.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, List

from framework.errors import SecurityViolationError
from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event
from src.services.llm_runtime import provider_metadata, request_advisory

from src.services import sanitization_service
from src.services.runtime_config import load_config

MANDATORY_DISCLAIMER = (
    "This briefing is decision support only. It does not autonomously determine "
    "safeguarding actions, distribute instructions to staff, or update policy registers."
)


class BriefingGenerationNode(FunctionNode):
    """Generate Markdown briefing and enforce the output data boundary."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    # ── S-3 output gate ───────────────────────────────────────────────────
    def _extra_security_gate_output(self, result: dict) -> dict:
        """Block credentials/sensitive patterns from briefing output."""
        config = load_config()
        patterns = config.get("output_credential_patterns", [])
        scan_scope = {
            "briefing_draft": result.get("briefing_draft", ""),
            "formatted_output": result.get("formatted_output", ""),
        }
        findings = sanitization_service.scan_for_sensitive(scan_scope, patterns)
        if findings:
            raise SecurityViolationError(
                "S-3: credential/sensitive content detected in briefing output — " f"paths: {', '.join(findings[:5])}"
            )
        # Verify mandatory disclaimer is present in any non-empty briefing.
        draft = result.get("briefing_draft", "")
        if draft and "does not autonomously determine" not in draft:
            raise SecurityViolationError("S-3: mandatory disclaimer missing from briefing_draft")
        return result

    # ── execute (Step 4 logic) ────────────────────────────────────────────
    def __init__(self, llm: object | None = None, config: dict | None = None) -> None:
        super().__init__()
        self._llm = llm
        self._config = config or {}

    def execute(self, state: dict) -> dict:
        if state.get("input_error_message"):
            message = str(state["input_error_message"])
            return {"status": AgentStatus.SUCCESS.value, "result": message, "formatted_output": message}

        request_advisory(
            state,
            "Review the EDU-C2-050 result for clarity, grounding, and safe human review.",
            self._llm,
            timeout_s=float(self._config.get("timeout_s", 30.0)),
            max_retry=int(self._config.get("max_retry", 3)),
        )
        metadata = provider_metadata(state)
        retrieval_complete: bool = state.get("retrieval_complete", False)
        warnings: List[str] = list(state.get("review_warnings", []) or [])
        error_log: List[str] = list(state.get("error_log", []) or [])

        if not retrieval_complete:
            warnings.append(
                "BriefingGenerationNode: retrieval_complete is False — " "no briefing generated; human review required"
            )
            emit_trace_event(
                "BriefingGenerationNode_briefing_skipped",
                {"reason": "retrieval_complete=False"},
                state,
            )
            return {
                "briefing_draft": "",
                "briefing_complete": False,
                "output_gate_passed": False,
                "formatted_output": "",
                "requires_human_review": True,
                "review_warnings": warnings,
                "error_log": error_log,
                "status": AgentStatus.ERROR.value,
                **metadata,
            }

        # Inner workflow failed (e.g. an unavailable credential or connector).
        # Report it on a SUCCESS envelope: the Marketplace runner only forwards
        # `output` when status == "success", so status=error would leave the
        # caller with no reason at all.
        if state.get("workflow_error_message"):
            reason = str(state["workflow_error_message"])
            message = (
                "The policy change briefing could not be completed.\n\n"
                f"Reason: {reason}\n\n"
                "How to continue:\n"
                "- Confirm the agent's required credentials are provisioned in this environment.\n"
                "- Verify the upstream services this agent depends on are reachable.\n"
                "- Retry once the issue above is resolved, or contact your administrator."
            )
            return {
                "status": AgentStatus.SUCCESS.value,
                "result": message,
                "formatted_output": message,
            }

        change_findings: List[Dict[str, Any]] = state.get("change_findings", []) or []
        source_results: List[Dict[str, Any]] = state.get("source_results", []) or []
        institution_name: str = state.get("institution_name", "Unknown Institution")
        review_period: str = state.get("review_period", "")
        baseline_age_warning: bool = state.get("baseline_age_warning", False)

        briefing = _build_briefing(
            institution_name=institution_name,
            review_period=review_period,
            source_results=source_results,
            change_findings=change_findings,
            baseline_age_warning=baseline_age_warning,
            warnings=warnings,
        )

        emit_trace_event(
            "BriefingGenerationNode_briefing_generated",
            {
                "institution_name": institution_name,
                "finding_count": len(change_findings),
                "source_count": len(source_results),
            },
            state,
        )
        return {
            "briefing_draft": briefing,
            "briefing_complete": True,
            "output_gate_passed": True,
            "formatted_output": briefing,
            "requires_human_review": True,
            "review_warnings": warnings,
            "error_log": error_log,
            "status": AgentStatus.SUCCESS.value,
            **metadata,
        }


# ── Briefing builder ──────────────────────────────────────────────────────────


def _build_briefing(
    institution_name: str,
    review_period: str,
    source_results: List[Dict[str, Any]],
    change_findings: List[Dict[str, Any]],
    baseline_age_warning: bool,
    warnings: List[str],
) -> str:
    lines: List[str] = []

    # Mandatory disclaimer — must appear first.
    lines.append(f"> **MANDATORY DISCLAIMER:** {MANDATORY_DISCLAIMER}")
    lines.append("")

    # Header.
    lines.append("# Safeguarding Policy Change Briefing")
    lines.append("")
    lines.append(f"**Institution:** {institution_name}")
    if review_period:
        lines.append(f"**Review Period:** {review_period}")

    # Sources and baselines.
    if source_results:
        lines.append("")
        lines.append("## Sources Reviewed")
        for sr in source_results:
            url = sr.get("url", "unknown")
            version = sr.get("version", "unknown")
            baseline_ref = ""
            # Retrieve baseline_ref from sanitized_sections if available.
            for sec in sr.get("sanitized_sections", []):
                baseline_ref = sec.get("baseline_ref", "")
                break
            lines.append(
                f"- `{url}` — version `{version}`" + (f" (baseline: `{baseline_ref}`)" if baseline_ref else "")
            )

    # Staleness warning.
    if baseline_age_warning:
        lines.append("")
        lines.append("> **Warning:** One or more baselines may be stale. Verify against the latest published guidance.")

    if warnings:
        lines.append("")
        lines.append("**Review warnings:**")
        for w in warnings:
            lines.append(f"- {w}")

    lines.append("")
    lines.append("---")

    # Findings grouped by classification.
    high = [f for f in change_findings if f.get("classification") == "High"]
    medium = [f for f in change_findings if f.get("classification") == "Medium"]
    low = [f for f in change_findings if f.get("classification") == "Low"]

    if not change_findings:
        lines.append("")
        lines.append("## Change Findings")
        lines.append("")
        lines.append("No material changes detected in the reviewed sources.")
    else:
        for label, group in (("High", high), ("Medium", medium), ("Low", low)):
            if not group:
                continue
            lines.append("")
            lines.append(f"## {label}-Significance Changes")
            lines.append("")
            for finding in group:
                lines.append(f"### {finding.get('section_id', 'unknown')}")
                lines.append(f"**Source:** `{finding.get('source_url', '')}`")
                lines.append(f"**Text Reference:** {finding.get('changed_text_ref', '')}")
                lines.append(f"**Classification:** {finding.get('classification', '')}")
                lines.append(f"**Cited Basis:** {finding.get('cited_basis', 'not cited')}")
                role_scope = finding.get("role_scope", [])
                if role_scope:
                    lines.append(f"**Role Scope:** {', '.join(role_scope)}")
                lines.append(f"**Confidence:** {finding.get('confidence', 0.0):.0%}")
                lines.append(f"**Rationale:** {finding.get('rationale', '')}")
                if finding.get("needs_human_confirmation"):
                    lines.append("- [ ] **Human confirmation required** — citation or confidence insufficient")
                lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "_This briefing was generated by SafeguardingPolicyChangeAgent (EDU-C2-050). "
        "It requires human review before any safeguarding action is taken._"
    )

    return "\n".join(lines)
