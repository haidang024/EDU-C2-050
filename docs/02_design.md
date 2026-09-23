# Template Design Specification — EDU-C2-050 SafeguardingPolicyChangeAgent

## Position in AgentCore Architecture

- **Agent Class**: Graph (src/graph/graph.py)
- **L1 Base**: AgentBaseGraph
- **Three-Layer Separation**:
  - State: flat TypedDict (`src/schemas/state.py`) — no Pydantic, no credentials
  - Node: L1 FunctionNode inheritance — `execute(self, state: dict) -> dict` only
  - Graph: outer `AgentBaseGraph` (graph.py) + inner `BaseGraph` (domain_workflow_graph.py)

## Architecture Overview

### Pipeline (4 steps)

```
Outer AgentBaseGraph:
  START → initialize → pre_process → main → post_process → finalize → END
                           ↑               ↑
                  Step 1 (VERIFIED_EXTERNAL)   Steps 2–3 via inner DomainWorkflowGraph

Inner DomainWorkflowGraph (inside `main` GraphNode slot):
  START → policy_retrieval → change_analysis → END
          (Step 2, ANON)      (Step 3, ANON)
```

### Node Configuration

| Step | Node Class | Slot | Trust | S-gate | Responsibility |
|------|-----------|------|-------|--------|----------------|
| 1 | `ConfigAndSourceValidationNode` | `pre_process` | VERIFIED_EXTERNAL | S-2 in: credential scan on source config | Validate operator config, resolve secrets, normalize sources |
| 2 | `PolicyRevisionRetrievalNode` | inner: `policy_retrieval` | ANONYMOUS | S-2 in: PII scan on sources | Retrieve sources, diff vs baseline, sanitize content |
| 3 | `ChangeAnalysisNode` | inner: `change_analysis` | ANONYMOUS | — | Classify High/Medium/Low with injected LLM and conservative fallback |
| 4 | `BriefingGenerationNode` | `post_process` | VERIFIED_EXTERNAL | S-3 out: credential scan + disclaimer check | Generate Markdown briefing with mandatory disclaimer |

### GraphNode Wrapper

`PolicyChangeGraphNode(GraphNode)` sits in the `main` slot of the outer graph.
- `get_subgraph()` → returns `DomainWorkflowGraph`
- `extract_input()` → serializes validated domain fields for the inner graph
- `_parent_config()` → passes runtime config and the injected `llm` client
- `merge_output()` → maps `source_results`, `retrieval_complete`, `change_findings`,
  `analysis_complete`, `audit_trace_refs`, `review_warnings`, `error_log`, `status`

### Data Flow

```
input_context["raw"] (JSON string)
    ↓ Step 1 — ConfigAndSourceValidationNode
validated_sources, institution_name, role_mappings, output_format,
review_period, significance_thresholds, max_baseline_age_days
    ↓ Step 2 — PolicyRevisionRetrievalNode (inner)
source_results [{url, format, status, version, content_hash,
                 sanitized_sections, citations, error_detail}]
retrieval_complete, baseline_age_warning
    ↓ Step 3 — ChangeAnalysisNode (inner)
change_findings [{section_id, source_url, changed_text_ref,
                  classification, cited_basis, role_scope,
                  confidence, needs_human_confirmation, rationale}]
analysis_complete
    ↓ Step 4 — BriefingGenerationNode
briefing_draft (Markdown), briefing_complete, output_gate_passed,
formatted_output, requires_human_review (always True)
```

### State Definition

| Field | Type | Purpose |
|-------|------|---------|
| `validated_sources` | `List[Dict]` | Normalized source list from Step 1 |
| `institution_name` | `str` | Name of the institution |
| `role_mappings` | `Dict[str, str]` | DSL/Governor display labels |
| `output_format` | `str` | "markdown" (default) |
| `review_period` | `str` | ISO interval |
| `significance_thresholds` | `Dict[str, float]` | `{high: 0.8, medium: 0.5}` |
| `max_baseline_age_days` | `int` | Staleness threshold (default 365) |
| `operator_authorized` | `bool` | True when VERIFIED_EXTERNAL (or higher) trust confirmed |
| `source_results` | `List[Dict]` | Per-source retrieval results with sanitized_sections |
| `retrieval_complete` | `bool` | False if any source failed |
| `baseline_age_warning` | `bool` | True when any baseline is stale |
| `change_findings` | `List[Dict]` | Classified findings per section |
| `analysis_complete` | `bool` | True when LLM classification finished |
| `briefing_draft` | `str` | Markdown briefing text |
| `briefing_complete` | `bool` | True when briefing generated |
| `output_gate_passed` | `bool` | True when S-3 scan passed |
| `requires_human_review` | `bool` | Always True |
| `audit_trace_refs` | `List[str]` | Safe correlation identifiers |
| `review_warnings` | `List[str]` | Cross-cutting warning messages |
| `error_log` | `List[str]` | Pipeline error messages |

**State Constraints (mandatory):**
- Flat TypedDict only (primitives + JSON-serializable types)
- No JWT, API keys, credentials in State (checkpoint DB leakage)
- InvocationContext via `InvocationContext.from_state(state)` inside nodes (not in State)
- No Pydantic models, dataclass, arbitrary Python objects (msgpack incompatible)

## Security Design

### S-1: Trust Gate
- `ConfigAndSourceValidationNode` requires `TrustLevel.VERIFIED_EXTERNAL`
- ANONYMOUS callers are rejected before `execute()` runs
- Inner nodes declare ANONYMOUS (trust verified once at boundary)
- `VERIFIED_EXTERNAL` (not `INTERNAL`) is the boundary level: the Marketplace runner
  stamps every authenticated caller `VERIFIED_EXTERNAL`
  (`shared/bootstrap/marketplace_app.py`) with no override, so an `INTERNAL` gate is
  unreachable on that deployment path and fails every invocation at S-1. Operator
  authorization is therefore enforced by caller authentication upstream, not by the
  trust enum alone.

### S-2: Input Gate (`_extra_security_gate_input`)
- Step 1: rejects credential/secret patterns (api_key, bearer, sk-…) in source config JSON
- Step 2: scans validated_sources for PII/case-reference patterns before retrieval

### S-3: Output Gate (`_extra_security_gate_output`)
- Step 4: scans `briefing_draft` and `formatted_output` for credential patterns
- Step 4: verifies mandatory disclaimer wording is present in non-empty briefing
- Raises `SecurityViolationError` on any match

### Secrets
- `SOURCE_CONNECTOR_TOKEN` — resolved via `ctx.secrets.require()` in Steps 1 and 2
- `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, and
  `AZURE_OPENAI_DEPLOYMENT` — resolved from the current invocation
- Provider credentials are never stored in State

### LLM Dependency Injection
- `server.py` loads `config/config.yaml` and provisions chained environment/domain secrets
- `Graph.register_nodes()` passes `self.config.get("llm")` to `PolicyChangeGraphNode`
- `PolicyChangeGraphNode._parent_config()` carries the same client into `DomainWorkflowGraph`
- `DomainWorkflowGraph.register_nodes()` constructs `ChangeAnalysisNode(llm=self.config.get("llm"))`
- With no key, the process boots and the analysis service uses its conservative deterministic classifier

### Retrieval Failure Policy
- If any source is unreachable in Step 2: hard stop — `retrieval_complete = False`
- Step 4 skips briefing generation if `retrieval_complete` is False
- No partial briefing is ever produced

## Framework Utilization

### Shared Components Used
- [x] `InvocationContext` — `ctx.secrets.require()` in Steps 1 and 2
- [x] `SecurityViolationError` — raised by S-2 (Step 1, 2) and S-3 (Step 4)
- [x] S-2: `_extra_security_gate_input()` — credential scan (Step 1), PII scan (Step 2)
- [x] S-3: `_extra_security_gate_output()` — credential + disclaimer scan (Step 4)
- [x] S-4: `emit_trace_event()` — at least one domain event per `execute()`
  - Step 1: `ConfigAndSourceValidationNode_config_validated` / `_config_rejected`
  - Step 2: `PolicyRevisionRetrievalNode_source_retrieved` (per source) / `_source_error`
  - Step 3: `ChangeAnalysisNode_analysis_complete`
  - Step 4: `BriefingGenerationNode_briefing_generated` / `_briefing_skipped`

### Composition Pattern
- **Pattern**: Cat 2 — outer `AgentBaseGraph` + inner `BaseGraph` via `GraphNode`
- **Inner graph**: `DomainWorkflowGraph` at `src/graph/domain_workflow_graph.py`
- **Error propagation**: `propagate` — inner errors surface as `SubgraphError`

## EU AI Act Art.13 Design-Time Evidence

The proposal declares this intended purpose outside Annex III, so Art.13 evidence
is not mandatory for this template. The following transparency controls are still
implemented as product safeguards.

| Evidence item | Design reference / description |
|---------------|--------------------------------|
| Intended purpose and operating context | Cited policy-change briefings for DSLs and Governors; no student-level decision-making |
| System capabilities and limitations | Retrieves declared sources, compares baselines, and classifies changes; cannot direct safeguarding action or update source systems |
| User-facing transparency information | Mandatory disclaimer and source/citation references in every non-empty briefing |
| Human oversight mechanism | `requires_human_review` is always true and outputs are intended for qualified staff review |

## Import Isolation Confirmation
- [x] Template does not import agenticstar-platform SDK (Level 0)
- [x] Import targets: `framework/` and `shared/` only

## Design Decision Record

| Decision | Option A | Option B | Chosen | Rationale |
|----------|----------|----------|--------|-----------|
| L1 base type | AgentBaseGraph | AutonomousBaseGraph | AgentBaseGraph | Linear pipeline; no autonomous loop |
| Inner graph parent | BaseGraph | AgentBaseGraph | BaseGraph | Custom node names (retrieval/analysis), no pre/main/post slots needed |
| Retrieval failure policy | Partial briefing | Hard stop | Hard stop | No partial briefing — safeguarding decisions must not be made on incomplete data |
| Trust level | VERIFIED_EXTERNAL | INTERNAL | VERIFIED_EXTERNAL | Not public-facing: ANONYMOUS is still rejected at S-1. INTERNAL was the original choice, but the Marketplace runner hardcodes VERIFIED_EXTERNAL for authenticated callers, making an INTERNAL gate unreachable (every invocation failed at S-1). Operator authorization is enforced by upstream caller authentication. |
| HITL | Enabled | Disabled | Disabled | Single-pass human-review aid; no in-graph interrupt required |
