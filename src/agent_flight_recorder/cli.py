"""Command-line interface."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .engine import run_scenario
from .models import Scenario, ValidationError
from .policy import Policy
from .report import render_demo_summary, write_run
from .research import render_research_prompt
from .rules import load_rules


def _json_files(path: str | Path) -> list[Path]:
    return sorted(item for item in Path(path).glob("*.json") if item.is_file())


def command_run(args: argparse.Namespace) -> int:
    scenario = Scenario.load(args.scenario)
    policy = Policy.load(args.policy)
    result = run_scenario(scenario, policy, load_rules(args.rules))
    output = write_run(result, args.output)
    print(f"{result.status}: {scenario.title} under {policy.id}")
    print(f"Report: {output / 'report.md'}")
    return 1 if args.fail_on_compromise and result.attack_success else 0


def command_demo(args: argparse.Namespace) -> int:
    scenarios = [Scenario.load(path) for path in _json_files(args.scenarios)]
    policies = [Policy.load(path) for path in _json_files(args.policies)]
    rules = load_rules(args.rules)
    if not scenarios or not policies:
        raise ValidationError("demo requires at least one scenario and policy")
    output = Path(args.output)
    results = []
    for scenario in scenarios:
        for policy in policies:
            result = run_scenario(scenario, policy, rules)
            write_run(result, output / policy.id / scenario.id)
            results.append(result)
    summary = render_demo_summary(results)
    output.mkdir(parents=True, exist_ok=True)
    (output / "summary.md").write_text(summary, encoding="utf-8")
    print(summary)
    print(f"Artifacts: {output}")
    return 0


def command_validate(args: argparse.Namespace) -> int:
    scenarios = [Scenario.load(path) for path in _json_files(args.scenarios)]
    policies = [Policy.load(path) for path in _json_files(args.policies)]
    rules = load_rules(args.rules)
    print(
        f"Validated {len(scenarios)} scenarios, {len(policies)} policies, "
        f"and {len(rules)} detection rules."
    )
    return 0


def command_research_prompt(args: argparse.Namespace) -> int:
    print(render_research_prompt(args.sources, args.since_days))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="afr",
        description="Replay-first security regression lab for AI agents and MCP workflows.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Replay one scenario under one policy")
    run_parser.add_argument("--scenario", required=True)
    run_parser.add_argument("--policy", required=True)
    run_parser.add_argument("--rules", default="rules/detections.json")
    run_parser.add_argument("--output", default="build/run")
    run_parser.add_argument("--fail-on-compromise", action="store_true")
    run_parser.set_defaults(func=command_run)

    demo_parser = subparsers.add_parser("demo", help="Compare every scenario and policy")
    demo_parser.add_argument("--scenarios", default="scenarios")
    demo_parser.add_argument("--policies", default="policies")
    demo_parser.add_argument("--rules", default="rules/detections.json")
    demo_parser.add_argument("--output", default="build/demo")
    demo_parser.set_defaults(func=command_demo)

    validate_parser = subparsers.add_parser("validate", help="Validate declarative artifacts")
    validate_parser.add_argument("--scenarios", default="scenarios")
    validate_parser.add_argument("--policies", default="policies")
    validate_parser.add_argument("--rules", default="rules/detections.json")
    validate_parser.set_defaults(func=command_validate)

    research_parser = subparsers.add_parser(
        "research-prompt", help="Render the bounded weekly research prompt"
    )
    research_parser.add_argument("--sources", default="research/sources.json")
    research_parser.add_argument("--since-days", type=int, default=14)
    research_parser.set_defaults(func=command_research_prompt)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        return int(args.func(args))
    except (OSError, ValueError, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
