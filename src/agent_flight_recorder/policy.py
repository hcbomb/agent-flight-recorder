"""Small deterministic policy engine used by the replay prototype."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json

from .models import Action, ValidationError


def get_path(document: dict[str, Any], dotted_path: str) -> Any:
    current: Any = document
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def condition_matches(document: dict[str, Any], condition: dict[str, Any]) -> bool:
    field = condition.get("field")
    operator = condition.get("op", "eq")
    expected = condition.get("value")
    if not isinstance(field, str):
        raise ValidationError("policy condition field must be a string")
    actual = get_path(document, field)
    if operator == "eq":
        return actual == expected
    if operator == "in":
        return isinstance(expected, list) and actual in expected
    if operator == "contains":
        return isinstance(actual, (str, list, tuple, dict)) and expected in actual
    if operator == "prefix":
        return isinstance(actual, str) and isinstance(expected, str) and actual.startswith(expected)
    if operator == "truthy":
        return bool(actual)
    raise ValidationError(f"unsupported policy operator: {operator!r}")


@dataclass(frozen=True)
class PolicyDecision:
    effect: str
    rule_id: str | None
    reason: str


@dataclass(frozen=True)
class PolicyRule:
    id: str
    effect: str
    reason: str
    conditions: tuple[dict[str, Any], ...]

    def matches(self, document: dict[str, Any]) -> bool:
        return all(condition_matches(document, item) for item in self.conditions)


@dataclass(frozen=True)
class Policy:
    id: str
    description: str
    default_effect: str
    rules: tuple[PolicyRule, ...]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        policy_id = data.get("id")
        if not isinstance(policy_id, str) or not policy_id:
            raise ValidationError("policy id must be a non-empty string")
        default_effect = data.get("default_effect", "allow")
        if default_effect not in {"allow", "deny"}:
            raise ValidationError("policy default_effect must be allow or deny")
        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            raise ValidationError("policy rules must be an array")
        rules: list[PolicyRule] = []
        for raw in raw_rules:
            if not isinstance(raw, dict):
                raise ValidationError("every policy rule must be an object")
            effect = raw.get("effect")
            if effect not in {"allow", "deny"}:
                raise ValidationError("policy rule effect must be allow or deny")
            conditions = raw.get("when", [])
            if not isinstance(conditions, list) or not conditions:
                raise ValidationError("policy rule when must be a non-empty array")
            rules.append(
                PolicyRule(
                    id=str(raw.get("id", "unnamed-rule")),
                    effect=effect,
                    reason=str(raw.get("reason", "policy rule matched")),
                    conditions=tuple(conditions),
                )
            )
        return cls(
            id=policy_id,
            description=str(data.get("description", "")),
            default_effect=default_effect,
            rules=tuple(rules),
        )

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def evaluate(self, action: Action, context: dict[str, Any]) -> PolicyDecision:
        document = {
            "action": {
                "kind": action.kind,
                "resource": action.resource,
                "trust": action.trust,
                "attributes": action.attributes,
                "attack_goal": action.attack_goal,
            },
            "context": context,
        }
        for rule in self.rules:
            if rule.matches(document):
                return PolicyDecision(rule.effect, rule.id, rule.reason)
        return PolicyDecision(
            self.default_effect,
            None,
            f"policy default: {self.default_effect}",
        )
