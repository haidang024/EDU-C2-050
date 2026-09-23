"""Graph — outer Cat 2 AgentBaseGraph for EDU-C2-050 (SafeguardingPolicyChangeAgent).

Backbone mapping:
  pre_process  → Step 1  ConfigAndSourceValidationNode (INTERNAL, S-2)
  main         → Steps 2–3 DomainWorkflowGraph          (inner, ANONYMOUS)
  post_process → Step 4  BriefingGenerationNode         (ANONYMOUS, S-3)

No autonomous loop, no conditional branches, no source-system write-back.
A retrieval failure hard-stops the pipeline — no partial briefing is produced.
"""

from __future__ import annotations

import re

import json
from typing import Any, ClassVar, cast

from framework.graph.agent_base_graph import AgentBaseGraph
from framework.graph.base_graph import BaseGraph
from framework.nodes.graph_node import GraphNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.nodes.post_process_node import BriefingGenerationNode
from src.nodes.pre_process_node import ConfigAndSourceValidationNode
from src.schemas.state import State


class PolicyChangeGraphNode(GraphNode):
    """Wraps the inner DomainWorkflowGraph in the `main` slot (Steps 2–3)."""

    # "handle" (not "propagate"): a propagated SubgraphError aborts the run
    # before merge_output(), so post_process never executes and the Marketplace
    # runner returns a bare RuntimeError with no reason. on_subgraph_error()
    # converts the failure into a domain field instead.
    error_strategy: ClassVar[str] = "handle"
    propagate_hitl: ClassVar[bool] = False

    def __init__(self, config: dict[str, Any] | None = None, llm: Any | None = None) -> None:
        super().__init__()
        self._config = dict(config or {})
        self._llm = llm

    def get_subgraph(self) -> BaseGraph:
        from src.graph.domain_workflow_graph import DomainWorkflowGraph

        return DomainWorkflowGraph(config=self._parent_config())

    def extract_input(self, state: AgentState) -> str:
        """Serialize validated domain fields for the inner graph boundary."""
        domain_keys = (
            "validated_sources",
            "significance_thresholds",
            "max_baseline_age_days",
            "review_warnings",
            "error_log",
        )
        return json.dumps({key: state[key] for key in domain_keys if key in state})

    def execute(self, state: AgentState) -> dict[str, Any]:
        if state.get("input_error_message"):
            return {"status": AgentStatus.SUCCESS.value}
        return cast(dict[str, Any], super().execute(state))

    def on_subgraph_error(self, state: AgentState, error: Exception) -> dict[str, Any]:
        """Carry an inner failure as a domain field so the pipeline keeps running.

        Returning status=error here would route straight to finalize, skipping
        post_process; the Marketplace runner then drops `output` and the caller sees
        only "invocation did not succeed".
        """
        error_log = getattr(error, "error_log", None) or []
        # A reason may name a missing secret (e.g. FOO_API_KEY). That is a key
        # *name*, not key material, but the S-3 output scan matches the literal
        # "api_key" substring and would reject the whole message. Mask such
        # identifiers so the diagnostic still reaches the caller.
        reasons = [
            re.sub(r"\b[A-Z0-9]+(?:_[A-Z0-9]+)*_(?:API_?KEY|KEY|TOKEN|SECRET|PASSWORD)\b", "<credential>", str(e))
            for e in error_log
            if str(e).strip()
        ]
        return {
            "status": AgentStatus.SUCCESS.value,
            "workflow_error_message": (
                reasons[-1] if reasons else "The policy change briefing workflow could not be completed."
            ),
        }

    def merge_output(self, state: AgentState, sub_result: dict) -> dict:
        """Map inner-graph results into outer state (explicit field mapping only)."""
        sub_result = sub_result or {}
        outer_warnings = state.get("review_warnings", []) or []
        inner_warnings = sub_result.get("review_warnings", []) or []
        merged_warnings = outer_warnings + [w for w in inner_warnings if w not in outer_warnings]
        outer_errors = state.get("error_log", []) or []
        inner_errors = sub_result.get("error_log", []) or []
        merged_errors = outer_errors + [e for e in inner_errors if e not in outer_errors]
        return {
            "source_results": sub_result.get("source_results", []),
            "retrieval_complete": sub_result.get("retrieval_complete", False),
            "baseline_age_warning": sub_result.get("baseline_age_warning", False),
            "change_findings": sub_result.get("change_findings", []),
            "analysis_complete": sub_result.get("analysis_complete", False),
            "audit_trace_refs": sub_result.get("audit_trace_refs", []),
            "review_warnings": merged_warnings,
            "error_log": merged_errors,
            "status": sub_result.get("status", AgentStatus.SUCCESS.value),
        }

    def _parent_config(self) -> dict[str, Any]:
        return {**self._config, "llm": self._llm}


class Graph(AgentBaseGraph):
    """Outer Cat 2 AgentBaseGraph for EDU-C2-050 (SafeguardingPolicyChangeAgent)."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    @property
    def name(self) -> str:
        return "edu_c2_050"

    @property
    def state_schema(self) -> type:
        return State

    def register_nodes(self) -> None:
        super().register_nodes()  # injects initialize + finalize
        self._nodes["pre_process"] = ConfigAndSourceValidationNode()  # FunctionNode — no args
        self._nodes["main"] = PolicyChangeGraphNode(
            config=self.config,
            llm=self.config.get("llm"),
        )
        self._nodes["post_process"] = BriefingGenerationNode(
            llm=self.config.get("llm"),
            config=self.config,
        )

    def get_output(self, state: AgentState) -> dict[str, Any]:
        output = cast(dict[str, Any], super().get_output(state))
        output["generation_mode"] = state.get("generation_mode")
        output["provider_error_message"] = state.get("provider_error_message")
        _set_marketplace_guidance(output, state, "Safeguarding policy change request")
        return output

    # add_edges() intentionally NOT overridden — backbone wiring is framework-owned.


def _set_marketplace_guidance(output: dict[str, Any], state: AgentState, subject: str) -> None:
    context = state.get("input_context")
    message = state.get("input_error_message")
    if not (isinstance(context, dict) and "conversation_history" in context and message):
        return
    lines = [f"{subject} could not be processed.", "", f"Reason: {message}"]
    guidance = state.get("input_error_guidance")
    if isinstance(guidance, list) and guidance:
        lines.extend(["", "How to continue:"])
        lines.extend(f"- {item}" for item in guidance)
    output["output"] = "\n".join(lines)
