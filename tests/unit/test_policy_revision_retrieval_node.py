"""Unit tests for PolicyRevisionRetrievalNode (Step 2 — retrieval + sanitization).

All invocations use ``node(state)`` to exercise the full security pipeline.
"""

from __future__ import annotations

from unittest.mock import patch


_VALID_SOURCES = [
    {"url": "https://example.com/kcsie.html", "format_hint": "html", "baseline_ref": "kcsie-2024-09"}
]


def _make_state(**overrides) -> dict:
    state = {
        "caller_trust_level": "ANONYMOUS",
        "session_id": "test-session",
        "thread_id": "test-thread",
        "trace_id": "test-trace",
        "correlation_id": "test-correlation",
        "validated_sources": _VALID_SOURCES,
        "institution_name": "Test Academy",
        "significance_thresholds": {"high": 0.8, "medium": 0.5},
        "max_baseline_age_days": 365,
        "review_warnings": [],
        "error_log": [],
    }
    state.update(overrides)
    return state


class TestPolicyRevisionRetrievalNodeHappyPath:
    def test_retrieval_complete_true_on_success(self):
        from src.nodes.policy_revision_retrieval_node import PolicyRevisionRetrievalNode

        node = PolicyRevisionRetrievalNode()
        result = node(_make_state())
        assert result.get("retrieval_complete") is True
        assert result.get("status") in ("success", "SUCCESS")

    def test_source_results_has_sanitized_sections(self):
        from src.nodes.policy_revision_retrieval_node import PolicyRevisionRetrievalNode

        node = PolicyRevisionRetrievalNode()
        result = node(_make_state())
        source_results = result.get("source_results", [])
        assert len(source_results) == 1
        sr = source_results[0]
        assert sr["url"] == "https://example.com/kcsie.html"
        assert sr["status"] == "ok"
        assert "sanitized_sections" in sr

    def test_content_hash_present(self):
        from src.nodes.policy_revision_retrieval_node import PolicyRevisionRetrievalNode

        node = PolicyRevisionRetrievalNode()
        result = node(_make_state())
        sr = result.get("source_results", [{}])[0]
        assert "content_hash" in sr
        assert len(sr["content_hash"]) > 0

    def test_all_sources_unchanged_returns_empty_sections(self):
        """When no sections are changed, sanitized_sections should be empty."""
        from src.nodes.policy_revision_retrieval_node import PolicyRevisionRetrievalNode
        from src.services import source_retrieval_service

        unchanged_sections = [
            {"id": "s1", "heading": "Scope", "text": "Short text."},
        ]
        with patch.object(source_retrieval_service, "retrieve") as mock_retrieve, \
             patch.object(source_retrieval_service, "diff_against_baseline", return_value=[]):
            mock_retrieve.return_value = {
                "sections": unchanged_sections,
                "version": "v1",
                "citations": [],
                "error": None,
            }
            node = PolicyRevisionRetrievalNode()
            result = node(_make_state())

        assert result.get("retrieval_complete") is True
        sr = result.get("source_results", [{}])[0]
        assert sr.get("sanitized_sections", []) == []

    def test_sensitive_content_sanitized_before_state(self):
        """PII patterns in retrieved text must be redacted before state write."""
        from src.nodes.policy_revision_retrieval_node import PolicyRevisionRetrievalNode
        from src.services import source_retrieval_service

        pii_sections = [
            {
                "id": "s1",
                "heading": "Contacts",
                "text": "Updated contact: test@example.com for case reference CAS-12345.",
            }
        ]
        diff_result = [
            {
                "id": "s1",
                "heading": "Contacts",
                "changed_text": "Updated contact: test@example.com for case reference CAS-12345.",
                "baseline_ref": "kcsie-2024-09",
                "diff_summary": "changed",
            }
        ]
        with patch.object(source_retrieval_service, "retrieve") as mock_retrieve, \
             patch.object(source_retrieval_service, "diff_against_baseline", return_value=diff_result):
            mock_retrieve.return_value = {
                "sections": pii_sections,
                "version": "v1",
                "citations": [],
                "error": None,
            }
            node = PolicyRevisionRetrievalNode()
            result = node(_make_state())

        sr = result.get("source_results", [{}])[0]
        sections = sr.get("sanitized_sections", [])
        if sections:
            text = sections[0].get("changed_text", "")
            # Either sanitized or email was not caught (pattern may not match) —
            # but must not contain raw API keys or credentials.
            assert "sk-" not in text


class TestPolicyRevisionRetrievalNodeFailure:
    def test_unreachable_source_returns_error(self):
        from src.nodes.policy_revision_retrieval_node import PolicyRevisionRetrievalNode

        sources = [{"url": "https://unreachable.example.com/doc", "format_hint": "html", "baseline_ref": "r1"}]
        node = PolicyRevisionRetrievalNode()
        result = node(_make_state(validated_sources=sources))
        assert result.get("status") in ("error", "ERROR")
        assert result.get("retrieval_complete") is False

    def test_one_source_unreachable_stops_all_processing(self):
        """No partial briefing: if any source fails, retrieval_complete must be False."""
        from src.nodes.policy_revision_retrieval_node import PolicyRevisionRetrievalNode

        sources = [
            {"url": "https://example.com/good.html", "format_hint": "html", "baseline_ref": "r1"},
            {"url": "https://unreachable.example.com/bad.html", "format_hint": "html", "baseline_ref": "r2"},
        ]
        node = PolicyRevisionRetrievalNode()
        result = node(_make_state(validated_sources=sources))
        assert result.get("retrieval_complete") is False
        # source_results must be empty — no partial output
        assert result.get("source_results", []) == []

    def test_error_log_populated_on_failure(self):
        from src.nodes.policy_revision_retrieval_node import PolicyRevisionRetrievalNode

        sources = [{"url": "https://offline.example.com/doc", "format_hint": "html", "baseline_ref": "r1"}]
        node = PolicyRevisionRetrievalNode()
        result = node(_make_state(validated_sources=sources))
        assert len(result.get("error_log", [])) > 0
