"""runtime_config — loads config/config.yaml and merges with coded defaults."""

from __future__ import annotations

import pathlib
from typing import Any, Dict

_DEFAULTS: Dict[str, Any] = {
    "stg_mock_mode": False,
    "source_connector_secret_key": "SOURCE_CONNECTOR_TOKEN",
    "llm_provider": "azure_openai",
    "llm_model": "azure-openai-deployment",
    "llm_timeout_s": 30,
    "llm_narrative_timeout_s": 20,
    # Upper bound on per-section LLM classification calls per invocation.
    # classify_changes() calls the provider once per changed section, serially,
    # so wall-clock grows linearly with section count: an unbounded run against a
    # slow or unreachable provider reads as a hung agent in Marketplace Chat.
    # Sections beyond this cap use the deterministic classifier and are flagged
    # needs_human_confirmation. 0 disables LLM classification entirely.
    "max_llm_classifications": 6,
    "max_baseline_age_days": 365,
    "significance_thresholds": {"high": 0.8, "medium": 0.5},
    "source_sanitization_patterns": [
        r"\b\d{1,3}\s\w+\s(?:Street|Road|Lane|Avenue|Drive|Close|Court)\b",
        r"\b[A-Z]{1,2}\d{1,2}\s?\d[A-Z]{2}\b",
        r"\b(?:0\d{9,10}|\+44\d{9,10})\b",
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        r"\b[A-Z]{2}\d{6}[A-Z]\b",
        r"(?i)\bcase\s*(?:ref|reference|no|number)[:\s]+\S+",
    ],
    "output_credential_patterns": [
        r"(?i)(api[_\-]?key|secret|password|token|bearer)[=:\s]+\S+",
        r"\bsk-[A-Za-z0-9]{20,}\b",
        r"\b[A-Za-z0-9+/]{40,}={0,2}\b",
    ],
}

_CONFIG_PATH = pathlib.Path(__file__).parents[2] / "config" / "config.yaml"
_cached: Dict[str, Any] | None = None


def mock_mode() -> bool:
    """Return True when running in STG/CI mock mode.

    Value is sourced from config.yaml (stg_mock_mode key) — never os.environ.
    """
    return bool(load_config().get("stg_mock_mode", False))


def load_config() -> Dict[str, Any]:
    """Return merged runtime config (file values override coded defaults)."""
    global _cached
    if _cached is not None:
        return _cached

    merged = dict(_DEFAULTS)
    if _CONFIG_PATH.exists():
        try:
            import yaml  # type: ignore[import-untyped]

            with _CONFIG_PATH.open("r", encoding="utf-8") as fh:
                file_cfg = yaml.safe_load(fh) or {}
            merged.update({k: v for k, v in file_cfg.items() if v is not None})
        except Exception:  # noqa: BLE001
            pass  # fall back to defaults if YAML is missing or malformed

    _cached = merged
    return merged
