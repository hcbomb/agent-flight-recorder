"""Deterministic replay engine."""

from __future__ import annotations

from hashlib import sha256

from .models import Event, RunResult, Scenario
from .policy import Policy
from .rules import DetectionRule, evaluate_rules


TAINTING_KINDS = {"content.read", "mcp.response.read", "tool.output.read"}


def run_scenario(
    scenario: Scenario,
    policy: Policy,
    detection_rules: tuple[DetectionRule, ...],
) -> RunResult:
    trace_seed = f"{scenario.id}:{policy.id}:schema-0.1"
    trace_id = f"afr-{sha256(trace_seed.encode()).hexdigest()[:16]}"
    context: dict[str, object] = {"tainted": False, "source_chain": []}
    events: list[Event] = []

    for action in scenario.actions:
        decision = policy.evaluate(action, context)
        tainted_after = bool(context["tainted"]) or (
            decision.effect == "allow"
            and action.trust == "untrusted"
            and action.kind in TAINTING_KINDS
        )
        if tainted_after and not context["tainted"]:
            context["source_chain"] = [action.resource]
        context["tainted"] = tainted_after

        events.append(
            Event(
                trace_id=trace_id,
                scenario_id=scenario.id,
                offset_ms=action.sequence * 10,
                sequence=action.sequence,
                kind=action.kind,
                resource=action.resource,
                trust=action.trust,
                attributes=action.attributes,
                context_tainted=tainted_after,
                policy_effect=decision.effect,
                policy_rule_id=decision.rule_id,
                policy_reason=decision.reason,
                attack_goal=action.attack_goal,
            )
        )
        if decision.effect == "deny":
            break

    event_tuple = tuple(events)
    detections = evaluate_rules(event_tuple, detection_rules)
    attack_success = any(
        event.attack_goal and event.policy_effect == "allow" for event in event_tuple
    )
    blocked = any(event.policy_effect == "deny" for event in event_tuple)
    return RunResult(
        scenario=scenario,
        policy_id=policy.id,
        trace_id=trace_id,
        events=event_tuple,
        detections=detections,
        attack_success=attack_success,
        blocked=blocked,
    )
