# Architecture

Agent Flight Recorder 0.1 is deliberately small and replay-first.

```text
Scenario JSON ──> Replay engine ──> Policy decision ──> Normalized event
                                          │                    │
                                          └── allow/deny       v
                                                   Sequence detections
                                                            │
                                                            v
                                               JSON + JSONL + Markdown
```

## Trust and Taint

Reading untrusted repository content, MCP responses, or tool output marks the
replay context as tainted. Taint is trace-local provenance, not proof that the
content is malicious. Policies can use it to require a stronger boundary for a
subsequent sensitive action.

## Enforcement

The built-in policy engine evaluates action metadata and trace context. It is
deterministic and first-match-wins. It supports enough operators to demonstrate
the boundary without pretending to replace Open Policy Agent, Cedar, or a
production authorization service.

## Detection

Detection rules are ordered behavioral sequences over the normalized events.
Rules evaluate attempted actions, including denied actions. This lets a team
distinguish prevention from visibility: a control can contain an action while a
detection still records that the chain occurred.

## Safety

The replay engine has no code-execution or networking primitive. A future live
adapter should convert observed events into this schema while keeping the
replay engine independent and testable.
