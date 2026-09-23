# Test Specification

## Test Strategy
- Coverage target: 80% for domain modules
- Test types: Unit, proof-of-boundary, and integration

## Framework Compliance Tests (Mandatory)

| TC-ID | Test | Expected Result | Result |
|-------|------|----------------|--------|
| TC-01 | State contract: flat TypedDict | Type check pass, no Pydantic/dataclass | |
| TC-02 | SecurityViolationError fires on invalid input | Error raised | |
| TC-03 | No JWT/Credential in State | CI `gate-credential-scan`: 0 violations (S-5 enforcement is performed in CI) | |
| TC-04 | InvocationContext constructed only via `from_state()` inside nodes | Direct `InvocationContext(...)` construction inside a node is flagged; the standalone adapter is exempt | Pass |
| TC-05 | S-4: no duplicate lifecycle events in `execute()` | `node_start` / `node_complete` / `node_error` absent from `execute()` body | 0 duplicates |
| TC-06 | S-2: `_security_gate_input()` not overridden (`FunctionNode` subclass) | `TypeError` raised at class definition if overridden (`@final` enforced by framework) | 0 overrides |
| TC-07 | S-3: `_security_gate_output()` not overridden (`FunctionNode` subclass) | `TypeError` raised at class definition if overridden (`@final` enforced by framework) | 0 overrides |
| TC-08 | `required_trust_level` declared and enforced | Insufficient trust is refused before `execute()` | Pass |
| TC-09 | S-2: `_extra_security_gate_input()` non-trivial when domain checks needed | Domain-specific input checks execute correctly (e.g. PII scan on additional fields, consent validation, business rules) | Hook body non-trivial |
| TC-10 | S-3: `_extra_security_gate_output()` non-trivial when domain checks needed | Domain-specific output checks execute correctly (e.g. nested credential scan, PII re-check, content filtering, preservation verification) | Hook body non-trivial |
| TC-11 | S-4: at least one domain `emit_trace_event()` inside each `execute()` | Domain event emitted on every invocation path | ≥1 per FunctionNode; delegating GraphNode exempt |

## Proof-of-Boundary Tests (Mandatory)

| PB-ID | Boundary | Test | Expected Result | Result |
|-------|----------|------|----------------|--------|
| PB-1 | BaseNode → EventEmitter | `emit_trace_event()` fires on every invocation path | No silent failures | |
| PB-2 | State serialization | Post-invoke State is primitives only | No Pydantic/dataclass | |
| PB-3 | L1 template boundary → External service | Connector service boundary is isolated and exercised with synthetic fixtures | Data retrieved or safe hard-stop | |
| PB-4 | Import isolation | No Level 0 imports | AST scan: 0 violations | |
| PB-5 | Checkpoint safety *(conditional)* | When checkpointing and framework ingress hooks are enabled, inspect all persistence surfaces | Inspection pass; otherwise auto-waived | Auto-waived — checkpointing disabled |
| PB-6 | Invoke execution order | `__call__()`: S-1 trust gate → S-4 `node_start` → S-2 `_security_gate_input` → `execute()` → S-3 `_security_gate_output` → S-4 `node_complete` | Order verified | |
| PB-7 | HITL interrupt propagation *(conditional)* | Required only when `config.yaml` sets `hitl.enabled: true`; otherwise record **Auto-waived — non-HITL** | `GraphInterrupt` propagates to the LangGraph engine; `status` is not set to `error` | |

> **Pre-CoE gate checklist:** PB-1 through PB-4 and PB-6 are mandatory. PB-5 is
> conditional on checkpointing plus framework ingress hooks. PB-7 is conditional
> on `hitl.enabled: true`; this project records **Auto-waived — non-HITL**.

## Business Logic Tests

| TC-ID | Test | Input | Expected Result | Result |
|-------|------|-------|----------------|--------|
| BL-01 | Valid source config | Synthetic JSON request | Normalized source list and operator authorization | Pass |
| BL-02 | Retrieval failure | Synthetic connector error | Hard stop; no partial briefing | Pass |
| BL-03 | Mandatory policy language | Sanitized changed section | High-significance cited finding | Pass |
| BL-04 | Briefing generation | Complete findings and source results | Markdown output includes disclaimer and human-review flag | Pass |
| BL-05 | Invocation-scoped LLM | Azure invocation credentials present/absent | Client resolves inside the node; provider failure uses safe fallback | Pass |

## Test Execution Summary
- Execution date: 
- Total tests: 
- Pass: / Fail: / Skip: 
- Coverage: ___%
