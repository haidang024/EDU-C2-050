"""ChangeAnalysisNode — Step 3 LLM-backed change classification.

Inner domain node (DomainWorkflowGraph, ANONYMOUS). Reads sanitized_sections from
source_results, classifies each changed section High/Medium/Low with citation
evidence, and flags uncertain or uncited findings for human confirmation.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.services import analysis_service
from src.services.runtime_config import load_config


class ChangeAnalysisNode(FunctionNode):
    """Classify policy changes High/Medium/Low with mandatory citations."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def __init__(self, llm: Any | None = None) -> None:
        super().__init__()
        self._llm = llm

    def _extra_security_gate_input(self, state: dict) -> dict:
        """Non-error path — return state unchanged."""
        return state

    def execute(self, state: dict) -> dict:
        config = load_config()
        source_results: List[Dict[str, Any]] = state.get("source_results", []) or []
        thresholds: Dict[str, float] = state.get("significance_thresholds") or config.get(
            "significance_thresholds", {"high": 0.8, "medium": 0.5}
        )

        # Collect all sanitized changed sections across all sources.
        all_sections: List[Dict[str, Any]] = []
        for sr in source_results:
            url = sr.get("url", "")
            for section in sr.get("sanitized_sections", []):
                enriched = dict(section)
                enriched["source_url"] = url
                all_sections.append(enriched)

        if not all_sections:
            # No changed sections — analysis is complete with empty findings.
            emit_trace_event(
                "ChangeAnalysisNode_analysis_complete",
                {"finding_count": 0, "source_count": len(source_results)},
                state,
            )
            return {
                "change_findings": [],
                "analysis_complete": True,
                "status": AgentStatus.SUCCESS.value,
            }

        findings = analysis_service.classify_changes(
            sections=all_sections,
            thresholds=thresholds,
            llm=self._llm,
            model=config.get("llm_model", "gpt-4o-mini"),
            timeout=int(config.get("llm_timeout_s", 30)),
            max_retry=int(config.get("max_retry", 1)),
            state=state,
            max_llm_classifications=int(config.get("max_llm_classifications", 6)),
        )

        # Post-process: ensure every finding has a citation; flag uncited ones.
        for finding in findings:
            if not finding.get("cited_basis"):
                finding["needs_human_confirmation"] = True
            if finding.get("confidence", 1.0) < thresholds.get("medium", 0.5):
                finding["needs_human_confirmation"] = True

        high_count = sum(1 for f in findings if f.get("classification") == "High")
        human_conf_count = sum(1 for f in findings if f.get("needs_human_confirmation"))

        emit_trace_event(
            "ChangeAnalysisNode_analysis_complete",
            {
                "finding_count": len(findings),
                "high_count": high_count,
                "needs_human_confirmation_count": human_conf_count,
            },
            state,
        )
        return {
            "change_findings": findings,
            "analysis_complete": True,
            "status": AgentStatus.SUCCESS.value,
        }
