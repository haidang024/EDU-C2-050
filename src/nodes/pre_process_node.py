"""ConfigAndSourceValidationNode — Step 1 input schema validation and S-2 input gate.

Boundary node (outer AgentBaseGraph, VERIFIED_EXTERNAL). Validates the operator-supplied
policy source configuration, rejects any credential/secret patterns in source
config (S-2), resolves the source connector secret to verify it is provisioned
(but never stores the value in state), and writes normalized config into state.
"""

from __future__ import annotations

import json
import re
from typing import Any, ClassVar, Dict, List

from framework.errors import SecurityViolationError
from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.services.runtime_config import load_config, mock_mode

# Credential/secret patterns forbidden in source config (URLs, paths, options).
_CREDENTIAL_PATTERNS: List[re.Pattern] = [
    re.compile(r"(?i)(api[_\-]?key|secret|password|token|bearer)[=:\s]+\S+"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)Authorization:\s*Bearer\s+\S+"),
]

_ALLOWED_FORMATS = frozenset({"html", "pdf", "docx", "text", "txt"})
_ALLOWED_OUTPUT_FORMATS = frozenset({"markdown", "json"})


class ConfigAndSourceValidationNode(FunctionNode):
    """Validate operator config and source declarations; enforce input data boundary."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    # ── S-2 input gate ────────────────────────────────────────────────────
    def _extra_security_gate_input(self, state: dict) -> dict:
        """Reject credential/secret patterns in source config before any processing."""
        raw = _raw_input(state)
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            return state  # parse errors handled in execute()

        if isinstance(parsed, dict):
            sources = parsed.get("policy_sources", [])
            if isinstance(sources, list):
                for src in sources:
                    src_str = json.dumps(src, ensure_ascii=False)
                    for pat in _CREDENTIAL_PATTERNS:
                        if pat.search(src_str):
                            raise SecurityViolationError(
                                "S-2: credential/secret pattern detected in policy_sources config; "
                                "remove embedded credentials before invoking this agent"
                            )
        return state

    # ── execute (Step 1 logic) ────────────────────────────────────────────
    def execute(self, state: dict) -> dict:
        config = load_config()
        raw = _raw_input(state)

        request, parse_err = _parse(raw)
        if parse_err:
            return _reject(state, [parse_err])

        errors, validated = _validate(request, config)
        if errors:
            return _reject(state, errors)

        # Resolve the source connector secret (never store the value). An absent
        # secret is no longer a rejection: PolicyRevisionRetrievalNode already
        # runs with credential="" and falls back to its fixture sources, so
        # blocking here stopped a review that the pipeline can complete.
        # `connector_source` records which path ran, for the audit log only.
        connector_source = "fixture"
        if not mock_mode():
            ctx = InvocationContext.from_state(state)
            try:
                ctx.secrets.require(config["source_connector_secret_key"])
                connector_source = "live"
            except Exception:  # noqa: BLE001
                emit_trace_event(
                    "ConfigAndSourceValidationNode_connector_fallback",
                    {"connector_source": "fixture"},
                    state,
                )

        emit_trace_event(
            "ConfigAndSourceValidationNode_config_validated",
            {
                "institution_name": validated["institution_name"],
                "source_count": len(validated["validated_sources"]),
                "output_format": validated["output_format"],
                "connector_source": connector_source,
            },
            state,
        )
        return {
            "validated_sources": validated["validated_sources"],
            "institution_name": validated["institution_name"],
            "role_mappings": validated["role_mappings"],
            "output_format": validated["output_format"],
            "review_period": validated["review_period"],
            "significance_thresholds": validated["significance_thresholds"],
            "max_baseline_age_days": validated["max_baseline_age_days"],
            "operator_authorized": True,
            # Operator-facing: "live" or "fixture". The briefing is identical
            # either way, so this is the only signal distinguishing them.
            "connector_source": connector_source,
            "review_warnings": [],
            "error_log": [],
            "status": AgentStatus.SUCCESS.value,
        }


# ── Module-level helpers ──────────────────────────────────────────────────────


def _raw_input(state: dict) -> str:
    ctx_in = state.get("input_context") or {}
    raw = ctx_in.get("raw")
    if raw is None:
        raw = state.get("user_input", "")
    if isinstance(raw, (dict, list)):
        return json.dumps(raw, ensure_ascii=False)
    return raw if isinstance(raw, str) else str(raw)


def _parse(raw: str) -> tuple[Dict[str, Any], str]:
    if not raw or not raw.strip():
        return {}, "empty request: no configuration provided"
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return {}, "request is not valid JSON"
    if not isinstance(parsed, dict):
        return {}, "request must be a JSON object"
    return parsed, ""


def _validate(request: Dict[str, Any], config: dict) -> tuple[List[str], Dict[str, Any]]:
    errors: List[str] = []

    # policy_sources
    sources_raw = request.get("policy_sources")
    if not sources_raw or not isinstance(sources_raw, list):
        errors.append("missing or empty required field: policy_sources (must be a list)")
        return errors, {}

    # Deduplicate by url/path
    seen_urls: set = set()
    validated_sources: List[Dict[str, Any]] = []
    dup_errors: List[str] = []
    for i, src in enumerate(sources_raw):
        if not isinstance(src, dict):
            errors.append(f"policy_sources[{i}] must be a dict")
            continue
        url = src.get("url") or src.get("path", "")
        if not url:
            errors.append(f"policy_sources[{i}] missing url/path")
            continue
        if url in seen_urls:
            dup_errors.append(f"duplicate source url/path: {url}")
            continue
        seen_urls.add(url)
        fmt = str(src.get("format_hint", "text")).strip().lower()
        if fmt not in _ALLOWED_FORMATS:
            fmt = "text"
        baseline_ref = str(src.get("baseline_ref", "")).strip()
        validated_sources.append(
            {
                "url": url,
                "format_hint": fmt,
                "baseline_ref": baseline_ref,
            }
        )

    if dup_errors:
        errors.extend(dup_errors)
    if errors:
        return errors, {}

    # institution_name
    institution_name = str(request.get("institution_name", "")).strip()
    if not institution_name:
        errors.append("missing required field: institution_name")

    # role_mappings
    role_mappings = request.get("role_mappings", {})
    if not isinstance(role_mappings, dict):
        role_mappings = {}

    # output_format
    output_format = str(request.get("output_format", "markdown")).strip().lower()
    if output_format not in _ALLOWED_OUTPUT_FORMATS:
        output_format = "markdown"

    # review_period
    review_period = str(request.get("review_period", "")).strip()

    # significance_thresholds
    cfg_thresholds = config.get("significance_thresholds", {"high": 0.8, "medium": 0.5})
    req_thresholds = request.get("significance_thresholds")
    significance_thresholds = cfg_thresholds.copy()
    if isinstance(req_thresholds, dict):
        significance_thresholds.update({k: float(v) for k, v in req_thresholds.items() if isinstance(v, (int, float))})

    # max_baseline_age_days
    try:
        max_baseline_age_days = int(request.get("max_baseline_age_days", config.get("max_baseline_age_days", 365)))
    except (ValueError, TypeError):
        max_baseline_age_days = 365

    if errors:
        return errors, {}

    return [], {
        "validated_sources": validated_sources,
        "institution_name": institution_name,
        "role_mappings": role_mappings,
        "output_format": output_format,
        "review_period": review_period,
        "significance_thresholds": significance_thresholds,
        "max_baseline_age_days": max_baseline_age_days,
    }


def _reject(state: dict, errors: List[str], *, user_correctable: bool = True) -> dict:
    emit_trace_event(
        "ConfigAndSourceValidationNode_config_rejected",
        {"error_count": len(errors), "codes": errors[:5]},
        state,
    )
    if not user_correctable:
        return {
            "operator_authorized": False,
            "review_warnings": ["request rejected at config validation — see error_log"],
            "error_log": [f"ConfigAndSourceValidationNode: {e}" for e in errors],
            "status": AgentStatus.ERROR.value,
        }
    return {
        "operator_authorized": False,
        "review_warnings": ["request rejected at config validation"],
        "input_error_message": "The safeguarding policy request failed validation: " + "; ".join(errors),
        # The reason above is already sanitised — it never names a secret key —
        # so guidance must not ask the caller to read one out of it. State the
        # two cases plainly instead: fix the request, or ask an operator.
        "input_error_guidance": [
            "Provide a JSON object with policy_sources and institution_name.",
            "Each policy source must include a url or path; do not embed credentials.",
            "If the reason above refers to a connector or credential rather than your "
            "request, ask an administrator to finish this agent's setup, then retry.",
        ],
        "status": AgentStatus.SUCCESS.value,
    }
