# Contributing

Contributions are welcome for safe scenarios, policy rules, detection rules,
documentation, tests, and adapters.

Before opening a pull request:

```bash
python -m unittest discover -s tests -v
PYTHONPATH=src python -m agent_flight_recorder.cli validate
PYTHONPATH=src python -m agent_flight_recorder.cli demo
```

New scenarios must follow `docs/adding-scenarios.md` and the constraints in
`SECURITY.md`. A scenario should fail open under `policies/baseline.json`, be
contained under `policies/hardened.json`, and trigger at least one detection.
