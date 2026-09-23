"""Unit tests for ChangeAnalysisNode (Step 3 — change classification).

All invocations use ``node(state)`` to exercise the full security pipeline.
"""

from __future__ import annotations


_BASE_SOURCE_RESULTS = [
    {
        "url": "https://example.com/kcsie.html",
        "format": "html",
        "status": "ok",
        "version": "v2025-abc",
        "content_hash": "abc123",
        "sanitized_sections": [
            {
                "id": "kcsie-s1",
                "heading": "Mandatory Reporting",
                "changed_text": (
                    "This section has been updated to clarify mandatory referral "
                    "obligations to children's social care. All DSLs must make an "
                    "immediate referral when abuse is suspected."
                ),
                "baseline_ref": "kcsie-2024-09",
                "diff_summary": "changed",
                "source_url": "https://example.com/kcsie.html",
            }
        ],
        "citations": [{"ref": "KCSIE-2024", "title": "Keeping Children Safe in Education 2024"}],
        "error_detail": None,
    }
]

_MEDIUM_SOURCE_RESULTS = [
    {
        "url": "https://example.com/doc.html",
        "format": "html",
        "status": "ok",
        "version": "v2025-xyz",
        "content_hash": "xyz456",
        "sanitized_sections": [
            {
                "id": "doc-s2",
                "heading": "Training Requirements",
                "changed_text": "All staff training requirements have been revised and updated.",
                "baseline_ref": "doc-2024",
                "diff_summary": "changed",
                "source_url": "https://example.com/doc.html",
            }
        ],
        "citations": [],
        "error_detail": None,
    }
]


def _make_state(**overrides) -> dict:
    state = {
        "caller_trust_level": "ANONYMOUS",
        "session_id": "test-session",
        "thread_id": "test-thread",
        "trace_id": "test-trace",
        "correlation_id": "test-correlation",
        "source_results": _BASE_SOURCE_RESULTS,
        "retrieval_complete": True,
        "significance_thresholds": {"high": 0.8, "medium": 0.5},
        "review_warnings": [],
        "error_log": [],
    }
    state.update(overrides)
    return state


class TestChangeAnalysisNodeHappyPath:
    def test_analysis_complete_true(self):
        from src.nodes.change_analysis_node import ChangeAnalysisNode

        node = ChangeAnalysisNode()
        result = node(_make_state())
        assert result.get("analysis_complete") is True
        assert result.get("status") in ("success", "SUCCESS")

    def test_findings_have_required_fields(self):
        from src.nodes.change_analysis_node import ChangeAnalysisNode

        node = ChangeAnalysisNode()
        result = node(_make_state())
        findings = result.get("change_findings", [])
        assert len(findings) > 0
        for f in findings:
            assert "section_id" in f
            assert "classification" in f
            assert f["classification"] in ("High", "Medium", "Low")
            assert "cited_basis" in f
            assert "rationale" in f
            assert "confidence" in f

    def test_high_classification_for_mandatory_language(self):
        from src.nodes.change_analysis_node import ChangeAnalysisNode

        node = ChangeAnalysisNode()
        result = node(_make_state())
        findings = result.get("change_findings", [])
        high = [f for f in findings if f["classification"] == "High"]
        # The mandatory/referral/social care language should produce at least one High
        assert len(high) >= 1

    def test_all_findings_have_citations(self):
        from src.nodes.change_analysis_node import ChangeAnalysisNode

        node = ChangeAnalysisNode()
        result = node(_make_state())
        for f in result.get("change_findings", []):
            if not f.get("cited_basis"):
                assert f.get("needs_human_confirmation") is True


class TestChangeAnalysisNodeNoSections:
    def test_empty_source_results_gives_empty_findings(self):
        from src.nodes.change_analysis_node import ChangeAnalysisNode

        node = ChangeAnalysisNode()
        result = node(_make_state(source_results=[]))
        assert result.get("analysis_complete") is True
        assert result.get("change_findings", []) == []
        assert result.get("status") in ("success", "SUCCESS")

    def test_no_sanitized_sections_gives_empty_findings(self):
        from src.nodes.change_analysis_node import ChangeAnalysisNode

        empty_source = [
            {
                "url": "https://example.com/doc.html",
                "format": "html",
                "status": "ok",
                "version": "v1",
                "content_hash": "abc",
                "sanitized_sections": [],
                "citations": [],
                "error_detail": None,
            }
        ]
        node = ChangeAnalysisNode()
        result = node(_make_state(source_results=empty_source))
        assert result.get("analysis_complete") is True
        assert result.get("change_findings", []) == []


class TestChangeAnalysisNodeHumanConfirmation:
    def test_low_confidence_sets_needs_human_confirmation(self):
        """Findings below medium threshold must set needs_human_confirmation True."""
        from src.nodes.change_analysis_node import ChangeAnalysisNode
        from unittest.mock import patch
        from src.services import analysis_service

        low_conf_findings = [
            {
                "section_id": "s1",
                "source_url": "https://example.com/doc.html",
                "changed_text_ref": "r1",
                "classification": "Medium",
                "cited_basis": "KCSIE-2024",
                "role_scope": ["dsl"],
                "confidence": 0.3,  # below medium threshold of 0.5
                "needs_human_confirmation": False,
                "rationale": "Low confidence finding.",
            }
        ]
        with patch.object(analysis_service, "classify_changes", return_value=low_conf_findings):
            node = ChangeAnalysisNode()
            result = node(_make_state(source_results=_BASE_SOURCE_RESULTS))

        findings = result.get("change_findings", [])
        assert any(f.get("needs_human_confirmation") is True for f in findings)

    def test_missing_citation_sets_needs_human_confirmation(self):
        from src.nodes.change_analysis_node import ChangeAnalysisNode
        from unittest.mock import patch
        from src.services import analysis_service

        uncited_findings = [
            {
                "section_id": "s1",
                "source_url": "https://example.com/doc.html",
                "changed_text_ref": "r1",
                "classification": "Medium",
                "cited_basis": "",  # empty → no citation
                "role_scope": ["dsl"],
                "confidence": 0.75,
                "needs_human_confirmation": False,
                "rationale": "Uncited finding.",
            }
        ]
        with patch.object(analysis_service, "classify_changes", return_value=uncited_findings):
            node = ChangeAnalysisNode()
            result = node(_make_state(source_results=_BASE_SOURCE_RESULTS))

        findings = result.get("change_findings", [])
        assert any(f.get("needs_human_confirmation") is True for f in findings)
