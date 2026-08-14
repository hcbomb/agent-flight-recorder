"""Behavioral sequence detection over normalized flight-recorder events."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json

from .models import Detection, Event, ValidationError
from .policy import get_path


def _event_matches(event: Event, expected: dict[str, Any]) -> bool:
    document = event.as_dict()
    for field, value in expected.items():
        if get_path(document, field) != value:
            return False
    return True


@dataclass(frozen=True)
class DetectionRule:
    id: str
    title: str
    severity: str
    description: str
    sequence: tuple[dict[str, Any], ...]

    def find(self, events: tuple[Event, ...]) -> Detection | None:
        cursor = 0
        matches: list[int] = []
        for event in events:
            if _event_matches(event, self.sequence[cursor]):
                matches.append(event.sequence)
                cursor += 1
                if cursor == len(self.sequence):
                    return Detection(
                        rule_id=self.id,
                        title=self.title,
                        severity=self.severity,
                        description=self.description,
                        matched_sequences=tuple(matches),
                    )
        return None


def load_rules(path: str | Path) -> tuple[DetectionRule, ...]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    raw_rules = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(raw_rules, list):
        raise ValidationError("detection rule file must contain a rules array")
    rules: list[DetectionRule] = []
    for raw in raw_rules:
        if not isinstance(raw, dict):
            raise ValidationError("every detection rule must be an object")
        sequence = raw.get("sequence")
        if not isinstance(sequence, list) or not sequence or not all(
            isinstance(item, dict) and item for item in sequence
        ):
            raise ValidationError("detection sequence must contain match objects")
        severity = str(raw.get("severity", "medium"))
        if severity not in {"low", "medium", "high", "critical"}:
            raise ValidationError(f"unsupported detection severity: {severity}")
        rules.append(
            DetectionRule(
                id=str(raw.get("id", "unnamed-detection")),
                title=str(raw.get("title", "Untitled detection")),
                severity=severity,
                description=str(raw.get("description", "")),
                sequence=tuple(sequence),
            )
        )
    return tuple(rules)


def evaluate_rules(
    events: tuple[Event, ...], rules: tuple[DetectionRule, ...]
) -> tuple[Detection, ...]:
    return tuple(detection for rule in rules if (detection := rule.find(events)))
