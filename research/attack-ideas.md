# Attack-Vector Backlog

This backlog is updated by the bounded weekly research task and reviewed by a
human before any candidate becomes an executable scenario.

| Candidate | Source date | Trust boundary | Safe simulation | Detection idea | Control idea | Priority | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Example: delegated identity confusion | — | User → agent → downstream API | Replay mismatched `on_behalf_of` metadata | Agent identity and user scope diverge | Verify both identities per action | Medium | Seed |

## Review Notes

- Reject duplicates of an implemented scenario.
- Prefer observable, deterministic behaviors over prompt-string signatures.
- Never add working exploit payloads or real target details.
