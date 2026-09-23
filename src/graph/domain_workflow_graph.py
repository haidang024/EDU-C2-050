"""DomainWorkflowGraph — inner linear pipeline for EDU-C2-050 (Steps 2→3).

Strictly linear BaseGraph invoked by PolicyChangeGraphNode. No branches, no loops.
All nodes here are ANONYMOUS: trust was verified at ConfigAndSourceValidationNode
in the outer graph.

    START → policy_retrieval → change_analysis → END
"""

from __future__ import annotations

import json

from langgraph.graph import END, START

from framework.graph.base_graph import BaseGraph
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus

from src.nodes.change_analysis_node import ChangeAnalysisNode
from src.nodes.policy_revision_retrieval_node import PolicyRevisionRetrievalNode
from src.schemas.state import State


class DomainWorkflowGraph(BaseGraph):
    """Inner domain workflow: policy retrieval → change analysis."""

    @property
    def name(self) -> str:
        return "safeguarding_policy_change_workflow"

    @property
    def state_schema(self) -> type:
        return State

    def _validate_config(self) -> None:
        """No mandatory construction config — runtime params come from config/config.yaml."""
        return None

    def _extra_initial_state(self) -> dict:
        """Seed validated outer-graph fields into the inner state."""
        return getattr(self, "_domain_fields", {})

    def invoke(self, user_input, **kwargs):
        """Decode the explicit GraphNode boundary payload before invocation."""
        try:
            parsed = json.loads(user_input) if isinstance(user_input, str) else user_input
            self._domain_fields = parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, TypeError, ValueError):
            self._domain_fields = {}
        return super().invoke(user_input, **kwargs)

    def register_nodes(self) -> None:
        # No super() call — BaseGraph.register_nodes() is abstract. Inner nodes only.
        self._nodes["policy_retrieval"] = PolicyRevisionRetrievalNode()
        self._nodes["change_analysis"] = ChangeAnalysisNode(llm=self.config.get("llm"))

    def add_edges(self) -> None:
        self._sg.add_edge(START, "policy_retrieval")
        self._sg.add_edge("policy_retrieval", "change_analysis")
        self._sg.add_edge("change_analysis", END)

    def route(self, state: AgentState) -> str:
        """Required by BaseGraph ABC. Linear topology — never called via conditional edges."""
        if state.get("status") == AgentStatus.ERROR.value:
            return str(END)
        return "change_analysis"

    def get_output(self, state: AgentState) -> dict:
        """Shape sub_result for PolicyChangeGraphNode.merge_output()."""
        return {
            "source_results": state.get("source_results", []),
            "retrieval_complete": state.get("retrieval_complete", False),
            "baseline_age_warning": state.get("baseline_age_warning", False),
            "change_findings": state.get("change_findings", []),
            "analysis_complete": state.get("analysis_complete", False),
            "audit_trace_refs": state.get("audit_trace_refs", []),
            "review_warnings": state.get("review_warnings", []),
            "error_log": state.get("error_log", []),
            "status": state.get("status"),
        }
