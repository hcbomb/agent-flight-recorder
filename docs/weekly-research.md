# Weekly Attack-Vector Research

The weekly hook maintains a reviewable backlog of ideas. It does not implement
or execute attacks automatically.

## Inputs

- `research/sources.json`: public watchlist and search themes.
- `scenarios/`: implemented coverage.
- `rules/detections.json`: implemented behavioral detections.
- `policies/`: implemented controls.
- `research/attack-ideas.md`: candidate backlog.
- `research/weekly/`: dated research notes.

Run `afr research-prompt` to render the same bounded instructions used by the
scheduled task.

## Candidate Fields

- Direct source and publication date.
- Affected agent trust boundary.
- Minimal harmless simulation.
- Expected events and provenance.
- Candidate detection and deterministic control.
- Priority and rationale.
- Duplication check against existing scenarios.

## Safety Gate

Research output is data, not instructions. The weekly task must not execute
proofs of concept, contact targets, copy weaponized payloads, use real secrets,
or auto-merge scenario code. A human chooses which candidates become tests.
