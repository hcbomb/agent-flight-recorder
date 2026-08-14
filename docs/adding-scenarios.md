# Adding Scenarios

Each scenario is a JSON file under `scenarios/` with:

- a stable `AFR-S###` identifier;
- a concise title, description, and attack-vector label;
- a public source URL when derived from research;
- two or more declarative actions;
- at least one action marked `attack_goal: true`.

Actions require `kind` and `resource`. `trust` is `trusted`, `internal`, or
`untrusted`. `attributes` may contain JSON-safe metadata used by a policy or
detection rule.

## Review Checklist

1. The scenario uses no executable payload.
2. External hosts use `.invalid` or a local fixture.
3. Secrets are named canaries and contain no real credential value.
4. The baseline policy lets the goal complete.
5. The hardened policy contains the goal.
6. At least one detection describes the behavioral chain.
7. Tests cover the expected results.

Keep the scenario minimal. Its purpose is to prove one trust-boundary failure,
not recreate every step of a real intrusion.
