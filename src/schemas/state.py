"""State — flat AgentState contract shared by the four EDU-C2-050 pipeline nodes.

ADR-005: State must be a flat TypedDict. LangGraph checkpoints use msgpack
serialization, so only plain JSON-serializable fields are allowed. No credentials,
no Pydantic/dataclass instances, no InvocationContext.

Data-boundary rule: individual student identity/contact/case data is prohibited
in every field below. Only sanitized policy text sections may be carried.
"""

from __future__ import annotations

from typing import Any, Dict, List

from framework.schemas.agent_state import AgentState


class State(AgentState):
    """Flat safeguarding-policy-change state.

    Inherited from AgentState: user_input, input_context, validated_input, result,
    formatted_output, status, session_id, correlation_id, node_history, error_log,
    hitl_* (unused — HITL disabled). Only agent-specific fields are declared here.
    """

    # ── Step 1 · ConfigAndSourceValidationNode (pre_process) ─────────────
    # Producer: ConfigAndSourceValidationNode. Consumer: Steps 2–4.
    validated_sources: List[Dict[str, Any]]  # [{url/path, format_hint, baseline_ref}]
    # Which source answered: "live" when the connector secret is provisioned,
    # "fixture" otherwise. Operator-facing only.
    connector_source: str | None
    institution_name: str  # name of the institution
    role_mappings: Dict[str, str]  # {role_key: display_label}
    output_format: str  # "markdown" (default)
    review_period: str  # ISO interval e.g. "2024-09-01/2025-09-01"
    significance_thresholds: Dict[str, float]  # {high: 0.8, medium: 0.5}
    max_baseline_age_days: int  # max age of baseline before warning
    operator_authorized: bool  # True when VERIFIED_EXTERNAL (or higher) trust confirmed

    # ── Step 2 · PolicyRevisionRetrievalNode (inner) ─────────────────────
    # Producer: PolicyRevisionRetrievalNode. Consumer: Step 3.
    # Per-source: {url, format, status, version, content_hash, sanitized_sections,
    #              citations, error_detail}
    source_results: List[Dict[str, Any]]
    retrieval_complete: bool  # False if any source failed
    baseline_age_warning: bool  # True when any baseline is stale

    # ── Step 3 · ChangeAnalysisNode (inner) ──────────────────────────────
    # Producer: ChangeAnalysisNode. Consumer: Step 4.
    # Per-finding: {section_id, source_url, changed_text_ref, classification,
    #               cited_basis, role_scope, confidence, needs_human_confirmation,
    #               rationale}
    change_findings: List[Dict[str, Any]]
    analysis_complete: bool

    # ── Step 4 · BriefingGenerationNode (post_process) ───────────────────
    # Producer: BriefingGenerationNode. Consumer: API caller (human reviewer).
    briefing_draft: str  # raw Markdown briefing text
    briefing_complete: bool
    output_gate_passed: bool  # True when S-3 scan passed
    requires_human_review: bool  # always True

    # ── Cross-cutting ─────────────────────────────────────────────────────
    audit_trace_refs: List[str]  # safe correlation/audit identifiers
    review_warnings: List[str]  # staleness/partial warnings (all steps)
    error_log: List[str]  # pipeline error messages
    input_error_message: str | None
    input_error_guidance: List[str]
    # Inner-workflow failure reason, carried as a domain field so the run keeps
    # a valid AgentStatus and still reaches post_process.
    workflow_error_message: str | None
    generation_mode: str | None
    provider_error_message: str | None
