---
name: session-lens
description: Show the user what Claude Code has stored about their sessions on this machine (transcripts, prompt history, file checkpoints, shell snapshots), find secrets such as API keys, tokens, private keys and passwords that leaked into them, and redact those secrets. Use when the user asks what is in their transcripts or session history, what Claude Code keeps or logs, whether a key or password leaked, to audit or clean up sessions, or says "session lens".
---

# Session Lens

Everything runs locally with Python 3 stdlib. Nothing is uploaded.

## Scan and report

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/lens.py" scan
```

This writes `~/.claude/session-lens/report.html` (mode 600), opens it in the browser, and prints a JSON summary. Secret values in the summary are masked; never try to recover or print the unmasked value.

Reply with, in this order:
1. Critical and high findings: type, masked value, how it got in (`where`: tool output = Claude read a file or ran a command that printed it; your prompt = pasted), and how many sessions. For each critical one, say plainly that the key must be rotated at its provider, because redacting local files does not revoke a key that was already sent to a model.
2. Scale: sessions, total size, distinct files read, commands run, oldest transcript, retention days (and whether that is the default).
3. The report path.
4. Next steps, only those that apply: redact; lower `cleanupPeriodDays`; add `permissions.deny` rules for secret files.

Do not paste the session list or file lists into chat; that is what the report is for.

## Redact

Always dry-run first and show the user the counts:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/lens.py" redact
```

Only after the user confirms, run with `--apply`. Transcripts modified in the last two minutes (this session) are skipped unless the user asks for `--include-active`. Redaction replaces each value with `[REDACTED:<rule>]` and keeps every transcript valid JSONL so sessions can still be resumed.

## Guard hook

The plugin also installs a hook that blocks prompts containing keys (bypass: include `#allow-secret`) and asks before Claude reads `.env`, SSH keys or cloud credential files. Disable with the environment variable `SESSION_LENS_GUARD=off`.
