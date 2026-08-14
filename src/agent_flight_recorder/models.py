"""Typed data structures and input validation for replay artifacts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
import json


class ValidationError(ValueError):
    """Raised when a declarative artifact is malformed."""


def _required_text(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{key!r} must be a non-empty string")
    return value.strip()


@dataclass(frozen=True)
class Action:
    sequence: int
    kind: str
    resource: str
    trust: str = "internal"
    attributes: dict[str, Any] = field(default_factory=dict)
    attack_goal: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any], sequence: int) -> "Action":
        attributes = data.get("attributes", {})
        if not isinstance(attributes, dict):
            raise ValidationError("action attributes must be an object")
        trust = data.get("trust", "internal")
        if trust not in {"trusted", "internal", "untrusted"}:
            raise ValidationError(f"unsupported trust value: {trust!r}")
        return cls(
            sequence=sequence,
            kind=_required_text(data, "kind"),
            resource=_required_text(data, "resource"),
            trust=trust,
            attributes=attributes,
            attack_goal=bool(data.get("attack_goal", False)),
        )


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    description: str
    attack_vector: str
    actions: tuple[Action, ...]
    source: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Scenario":
        raw_actions = data.get("actions")
        if not isinstance(raw_actions, list) or not raw_actions:
            raise ValidationError("scenario actions must be a non-empty array")
        actions = tuple(
            Action.from_dict(item, index)
            for index, item in enumerate(raw_actions, start=1)
            if isinstance(item, dict)
        )
        if len(actions) != len(raw_actions):
            raise ValidationError("every scenario action must be an object")
        if not any(action.attack_goal for action in actions):
            raise ValidationError("scenario must identify at least one attack_goal")
        source = data.get("source")
        if source is not None and not isinstance(source, str):
            raise ValidationError("scenario source must be a string when present")
        return cls(
            id=_required_text(data, "id"),
            title=_required_text(data, "title"),
            description=_required_text(data, "description"),
            attack_vector=_required_text(data, "attack_vector"),
            actions=actions,
            source=source,
        )

    @classmethod
    def load(cls, path: str | Path) -> "Scenario":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


@dataclass(frozen=True)
class Event:
    trace_id: str
    scenario_id: str
    offset_ms: int
    sequence: int
    kind: str
    resource: str
    trust: str
    attributes: dict[str, Any]
    context_tainted: bool
    policy_effect: str
    policy_rule_id: str | None
    policy_reason: str
    attack_goal: bool

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Detection:
    rule_id: str
    title: str
    severity: str
    description: str
    matched_sequences: tuple[int, ...]

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["matched_sequences"] = list(self.matched_sequences)
        return data


@dataclass(frozen=True)
class RunResult:
    scenario: Scenario
    policy_id: str
    trace_id: str
    events: tuple[Event, ...]
    detections: tuple[Detection, ...]
    attack_success: bool
    blocked: bool

    @property
    def status(self) -> str:
        if self.attack_success:
            return "COMPROMISED"
        if self.blocked:
            return "CONTAINED"
        return "NO_GOAL_REACHED"

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "0.1",
            "scenario": {
                "id": self.scenario.id,
                "title": self.scenario.title,
                "attack_vector": self.scenario.attack_vector,
                "source": self.scenario.source,
            },
            "policy_id": self.policy_id,
            "trace_id": self.trace_id,
            "status": self.status,
            "attack_success": self.attack_success,
            "blocked": self.blocked,
            "detections": [item.as_dict() for item in self.detections],
            "events": [item.as_dict() for item in self.events],
        }
