"""Shared pytest fixtures and session-wide setup for EDU-C2-050 tests.

Enables mock mode so unit tests skip real secret/connector calls.
The real wheel's InvocationContext.from_state() still works; only service
calls that would hit external endpoints are bypassed.
"""

def pytest_configure(config):
    """Enable mock mode for the entire test session via the config cache."""
    import src.services.runtime_config as rc
    rc._cached = {**(rc.load_config()), "stg_mock_mode": True}
