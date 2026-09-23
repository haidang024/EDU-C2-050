from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel

from src.graph.graph import Graph


def test_invalid_marketplace_policy_request_returns_readable_guidance():
    graph = Graph(config={})
    graph.compile()
    result = graph.invoke("Hello", ctx=InvocationContext(caller_trust_level=TrustLevel.INTERNAL), input_context={"conversation_history": []})
    assert result["status"] == "success"
    assert result["output"].startswith("Safeguarding policy change request could not be processed.")
    assert "failed validation" in result["output"]
