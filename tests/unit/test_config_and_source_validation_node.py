"""Unit tests for ConfigAndSourceValidationNode (Step 1 — config validation + S-2 gate).

All invocations use ``node(state)`` (not ``node.execute(state)``) to exercise
the full security pipeline. Fixtures use synthetic, non-personal data only.
"""

from __future__ import annotations

import json


_VALID_SOURCES = [
    {"url": "https://example.com/kcsie.html", "format_hint": "html", "baseline_ref": "kcsie-2024-09"}
]

_VALID_PAYLOAD = {
    "policy_sources": _VALID_SOURCES,
    "institution_name": "Test Academy",
    "role_mappings": {"dsl": "DSL", "deputy_dsl": "Deputy DSL"},
    "output_format": "markdown",
    "review_period": "2024-09-01/2025-09-01",
}


def _make_state(payload: dict | None = None, trust: str = "INTERNAL") -> dict:
    raw = json.dumps(payload if payload is not None else _VALID_PAYLOAD)
    return {
        "caller_trust_level": trust,
        "session_id": "test-session",
        "thread_id": "test-thread",
        "trace_id": "test-trace",
        "correlation_id": "test-correlation",
        "input_context": {"raw": raw},
        "user_input": raw,
    }


class TestConfigAndSourceValidationNodeHappyPath:
    def test_valid_config_written_to_state(self):
        from src.nodes.pre_process_node import ConfigAndSourceValidationNode

        node = ConfigAndSourceValidationNode()
        result = node(_make_state())
        assert result.get("status") in ("success", "SUCCESS")
        assert result.get("operator_authorized") is True
        assert result.get("institution_name") == "Test Academy"
        sources = result.get("validated_sources", [])
        assert len(sources) == 1
        assert sources[0]["url"] == "https://example.com/kcsie.html"
        assert sources[0]["format_hint"] == "html"

    def test_output_format_defaults_to_markdown(self):
        from src.nodes.pre_process_node import ConfigAndSourceValidationNode

        payload = {**_VALID_PAYLOAD}
        del payload["output_format"]
        node = ConfigAndSourceValidationNode()
        result = node(_make_state(payload))
        assert result.get("output_format") == "markdown"

    def test_significance_thresholds_merged(self):
        from src.nodes.pre_process_node import ConfigAndSourceValidationNode

        payload = {**_VALID_PAYLOAD, "significance_thresholds": {"high": 0.9}}
        node = ConfigAndSourceValidationNode()
        result = node(_make_state(payload))
        thresholds = result.get("significance_thresholds", {})
        assert thresholds.get("high") == 0.9
        # medium should come from config defaults
        assert "medium" in thresholds


class TestConfigAndSourceValidationNodeSchemaRejection:
    def test_missing_policy_sources_rejected(self):
        from src.nodes.pre_process_node import ConfigAndSourceValidationNode

        payload = {k: v for k, v in _VALID_PAYLOAD.items() if k != "policy_sources"}
        node = ConfigAndSourceValidationNode()
        result = node(_make_state(payload))
        assert result.get("status") in ("success", "SUCCESS")
        assert result.get("operator_authorized") is False
        assert "policy_sources" in result.get("input_error_message", "")

    def test_empty_institution_name_rejected(self):
        from src.nodes.pre_process_node import ConfigAndSourceValidationNode

        payload = {**_VALID_PAYLOAD, "institution_name": ""}
        node = ConfigAndSourceValidationNode()
        result = node(_make_state(payload))
        assert result.get("status") in ("success", "SUCCESS")
        assert result.get("operator_authorized") is False
        assert "institution_name" in result.get("input_error_message", "")

    def test_empty_policy_sources_list_rejected(self):
        from src.nodes.pre_process_node import ConfigAndSourceValidationNode

        payload = {**_VALID_PAYLOAD, "policy_sources": []}
        node = ConfigAndSourceValidationNode()
        result = node(_make_state(payload))
        assert result.get("status") in ("success", "SUCCESS")
        assert "policy_sources" in result.get("input_error_message", "")

    def test_duplicate_sources_rejected(self):
        from src.nodes.pre_process_node import ConfigAndSourceValidationNode

        dup_url = "https://example.com/kcsie.html"
        payload = {
            **_VALID_PAYLOAD,
            "policy_sources": [
                {"url": dup_url, "format_hint": "html", "baseline_ref": "r1"},
                {"url": dup_url, "format_hint": "html", "baseline_ref": "r2"},
            ],
        }
        node = ConfigAndSourceValidationNode()
        result = node(_make_state(payload))
        assert result.get("status") in ("success", "SUCCESS")
        assert "duplicate" in result.get("input_error_message", "")


class TestConfigAndSourceValidationNodeS2Gate:
    """S-2 gate: credential patterns in source config must be rejected."""

    def test_api_key_in_source_url_rejected(self):
        from framework.errors import SecurityViolationError
        from src.nodes.pre_process_node import ConfigAndSourceValidationNode

        payload = {
            **_VALID_PAYLOAD,
            "policy_sources": [
                {"url": "https://example.com/doc", "api_key": "secret=abc123token", "format_hint": "html", "baseline_ref": "r1"}
            ],
        }
        node = ConfigAndSourceValidationNode()
        try:
            result = node(_make_state(payload))
            assert result.get("status") in ("error", "ERROR"), (
                "S-2 gate must reject credential patterns in source config"
            )
        except SecurityViolationError:
            pass  # correct

    def test_bearer_token_in_source_config_rejected(self):
        from framework.errors import SecurityViolationError
        from src.nodes.pre_process_node import ConfigAndSourceValidationNode

        payload = {
            **_VALID_PAYLOAD,
            "policy_sources": [
                {"url": "https://example.com/doc", "auth": "bearer=sk-abc1234567890abcdefghij", "format_hint": "html", "baseline_ref": "r1"}
            ],
        }
        node = ConfigAndSourceValidationNode()
        try:
            result = node(_make_state(payload))
            assert result.get("status") in ("error", "ERROR"), (
                "S-2 gate must reject bearer token patterns in source config"
            )
        except SecurityViolationError:
            pass  # correct

    def test_non_json_input_rejected(self):
        from src.nodes.pre_process_node import ConfigAndSourceValidationNode

        node = ConfigAndSourceValidationNode()
        state = {
            "caller_trust_level": "INTERNAL",
            "session_id": "test-session",
            "thread_id": "test-thread",
            "trace_id": "test-trace",
            "correlation_id": "test-correlation",
            "input_context": {"raw": "not valid json {{{{"},
        }
        result = node(state)
        assert result.get("status") in ("success", "SUCCESS")
        assert "json" in result.get("input_error_message", "").lower()
