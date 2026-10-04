# Changelog

## 0.1.1

- **Scan now covers saved tool outputs.** Claude Code stores large tool results as separate files under `<session>/tool-results/`. `scan` only read `.jsonl` transcripts and missed them; it now reads every file under `projects/` and attributes saved outputs to their session. (`redact` already covered them.)
- **Fewer false positives.**
  - Card numbers inside URLs (`?id=…`, `/item/…`) are no longer flagged.
  - Assignments whose value is an ISO timestamp (`expires = 2026-09-21T20:54:38Z`) are ignored.
  - Token counters and code (`total_tokens = event.usage.output_tokens`) are ignored.
- Added regression tests (`tests/`), a "What it reads, writes and runs" section in the README, and `homepage` / `repository` in `plugin.json`.

## 0.1.0

First release: `scan` report, `redact`, guard hook, skill.
