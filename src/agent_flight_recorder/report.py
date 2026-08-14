"""Artifact writers for humans and machines."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable
import json

from .models import RunResult


def render_report(result: RunResult) -> str:
    lines = [
        f"# Flight Report: {result.scenario.title}",
        "",
        f"- Scenario: `{result.scenario.id}`",
        f"- Attack vector: `{result.scenario.attack_vector}`",
        f"- Policy: `{result.policy_id}`",
        f"- Trace: `{result.trace_id}`",
        f"- Outcome: **{result.status}**",
        f"- Detections: **{len(result.detections)}**",
        "",
        result.scenario.description,
        "",
        "## Event Timeline",
        "",
        "| Seq | Offset | Action | Resource | Trust | Tainted | Policy | Rule |",
        "| ---: | ---: | --- | --- | --- | --- | --- | --- |",
    ]
    for event in result.events:
        lines.append(
            f"| {event.sequence} | {event.offset_ms} ms | `{event.kind}` | "
            f"`{event.resource}` | {event.trust} | {str(event.context_tainted).lower()} | "
            f"**{event.policy_effect.upper()}** | `{event.policy_rule_id or 'default'}` |"
        )
    lines.extend(["", "## Detections", ""])
    if not result.detections:
        lines.append("No behavioral detection rule matched this trace.")
    for detection in result.detections:
        sequences = ", ".join(str(item) for item in detection.matched_sequences)
        lines.extend(
            [
                f"### {detection.rule_id}: {detection.title}",
                "",
                f"- Severity: **{detection.severity}**",
                f"- Matched event sequences: `{sequences}`",
                f"- {detection.description}",
                "",
            ]
        )
    lines.extend(
        [
            "## Interpretation",
            "",
            (
                "The simulated attack reached its declared goal. This policy does not "
                "contain the replayed chain."
                if result.attack_success
                else "A deterministic policy stopped the chain before its declared goal."
                if result.blocked
                else "The declared attack goal was not reached during this trace."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def write_run(result: RunResult, output: str | Path) -> Path:
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    (output_path / "result.json").write_text(
        json.dumps(result.as_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with (output_path / "trace.jsonl").open("w", encoding="utf-8") as handle:
        for event in result.events:
            handle.write(json.dumps(event.as_dict(), sort_keys=True) + "\n")
    (output_path / "report.md").write_text(render_report(result), encoding="utf-8")
    return output_path


def render_demo_summary(results: Iterable[RunResult]) -> str:
    result_list = list(results)
    policy_ids = sorted({item.policy_id for item in result_list})
    scenarios: dict[str, dict[str, RunResult]] = {}
    titles: dict[str, str] = {}
    for result in result_list:
        scenarios.setdefault(result.scenario.id, {})[result.policy_id] = result
        titles[result.scenario.id] = result.scenario.title

    headers = ["Scenario", *policy_ids]
    lines = [
        "# Agent Flight Recorder Demo",
        "",
        "This comparison replays the same safe attack metadata under each policy.",
        "",
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---", *(["---"] * len(policy_ids))]) + " |",
    ]
    for scenario_id in sorted(scenarios):
        cells = [titles[scenario_id]]
        for policy_id in policy_ids:
            result = scenarios[scenario_id].get(policy_id)
            cells.append(result.status if result else "NOT RUN")
        lines.append("| " + " | ".join(cells) + " |")
    lines.extend(
        [
            "",
            "`COMPROMISED` means the simulated goal was allowed. `CONTAINED` means a "
            "deterministic policy denied the chain before the goal completed.",
            "",
        ]
    )
    return "\n".join(lines)
