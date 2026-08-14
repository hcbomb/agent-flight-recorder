# Security Policy

## Prototype Boundary

Agent Flight Recorder 0.1 is a safe simulation and replay tool. Scenario files
contain action metadata, not executable exploit payloads. The engine never
opens network connections, reads real secrets, launches subprocesses, or writes
outside its requested report directory.

The `.invalid` top-level domain is used for simulated external destinations.
Canaries are identifiers such as `CANARY_DB_TOKEN`; they are not credentials.

## Responsible Scenario Contributions

Contributions must:

- use only harmless fixtures and reserved destinations;
- describe the minimum behavior needed to test a control;
- exclude working malware, credential theft, persistence, and evasion code;
- identify the expected telemetry, control, and safe success condition;
- cite public research without copying weaponized payloads.

Live adapters must default to deny external side effects and clearly document
their authorization boundary.

## Reporting a Vulnerability

Do not open a public issue for a vulnerability that could put users at risk.
Use GitHub's private vulnerability reporting feature when it is available for
this repository.
