# Session Lens

See what Claude Code keeps about your sessions on your own disk, find secrets that leaked into it, scrub them, and stop new ones getting in.

Free and local: Python 3 standard library, no network calls, no API key, works on any Claude plan.

![Session Lens report](docs/screenshots/report-light.jpg)

## Why

Every Claude Code session is saved as plain text under `~/.claude/`:

| Store | What's in it |
|---|---|
| `projects/<project>/<session>.jsonl` | Every prompt, reply, thinking block, tool call **and its full output**: whole files Claude read, command output, fetched pages |
| `history.jsonl` | Every prompt you typed, plus pastes |
| `file-history/` | Copies of files from before Claude edited them |
| `shell-snapshots/` | Your shell functions, aliases and options |

So if Claude ran `cat .env` once, those keys now sit in a transcript until the retention window (`cleanupPeriodDays`, default 30) deletes it, and they get copied by any backup or sync of your home directory.

## Install

```
/plugin marketplace add akhmadgo/session-lens
/plugin install session-lens@session-lens
```

## Use

Ask Claude *"what's in my session transcripts?"* or *"did any keys leak into my sessions?"*, or run it directly:

```bash
python3 scripts/lens.py scan            # opens ~/.claude/session-lens/report.html
python3 scripts/lens.py redact          # dry run: what would be replaced
python3 scripts/lens.py redact --apply  # replace each secret with [REDACTED:<type>]
```

The report shows:

- **Secrets**: API keys (Anthropic, OpenAI, AWS, GitHub, GitLab, Slack, Stripe, Google, npm, Hugging Face), private keys, JWTs, passwords in URLs, `*_SECRET=` / `*_TOKEN=` assignments, card numbers. Each is masked, fingerprinted, counted across every session, and labelled with how it got in (your prompt, tool output, Claude's reply).
- **Storage inventory**: every local store, its size, and what it holds.
- **Per-session detail**: project, branch, files read and changed, commands run, URLs fetched, MCP servers used.
- **Retention**: your current `cleanupPeriodDays` and the age of your oldest transcript.

See [`examples/sample-report.html`](examples/sample-report.html), generated from synthetic data.

Redaction keeps transcripts valid JSONL so `--resume` still works, rewrites atomically, skips binary files, and skips transcripts touched in the last two minutes (the live session) unless you pass `--include-active`.

**Redacting does not revoke a key.** Anything that appeared in a session was also sent to the model. Rotate it at the provider.

## What it reads, writes and runs

Nothing leaves your machine: no network calls, no telemetry, no third-party packages.

| | |
|---|---|
| **Reads** | `~/.claude/projects/` (transcripts and saved tool outputs), `history.jsonl`, `file-history/`, `paste-cache/`, `shell-snapshots/`, `todos/`, `debug/`, `settings.json`. Honors `CLAUDE_CONFIG_DIR`. |
| **Writes** | `~/.claude/session-lens/report.html` (mode 600). With `redact --apply`, rewrites the files above in place. |
| **Runs** | `python3` for the scripts and hook. `scan` opens the report with your system opener (`open` on macOS, `xdg-open` on Linux, `start` on Windows); pass `--no-open` to skip it. |
| **Hook** | Reads the prompt or tool call Claude Code passes to it on stdin, and prints an allow, ask or block decision. It stores nothing. |

## Guard hook (prevention)

Installed automatically with the plugin:

- **Prompts**: a prompt containing a critical or high-severity secret is blocked before it is saved. Add `#allow-secret` to send it anyway.
- **Tool calls**: Claude Code asks you first before Claude reads `.env`, SSH private keys, `*.pem`, `.npmrc`, `~/.aws/credentials`, kube/docker/gcloud credentials, or runs `printenv`, `gh auth token`, `cat secrets.yml` and similar.

Disable with `SESSION_LENS_GUARD=off`. The guard never fails closed: if it errors, the action goes through.

## Recommended settings

```json
{
  "cleanupPeriodDays": 7,
  "permissions": {
    "deny": ["Read(./.env)", "Read(./.env.*)", "Read(./secrets/**)"]
  }
}
```

## Field test

Numbers from running it on a real `~/.claude` before release. Only totals are shown here; no values from the scanned machine.

| | |
|---|---|
| Data scanned | 31 sessions, 31 MB of transcripts, plus prompt history, file checkpoints and shell snapshots |
| Scan time | about 5 s on a laptop |
| Retention | oldest transcript 26 days old against the default 30-day `cleanupPeriodDays` |
| Exposure | 23 distinct files whose full contents were kept in transcripts; 314 shell commands stored with their output |
| Findings | 12 medium-severity secret-looking assignments in tool output; no critical keys outside the deliberate test fixtures |

What testing changed:

- **Card numbers.** The first scan flagged about 150 "card numbers" in `history.jsonl`. They were 13-digit millisecond timestamps, about 1 in 10 of which pass the Luhn check by chance. The rule now requires real issuer prefixes (Visa, Mastercard, Amex, Discover) and real card lengths; the false positives went to zero.
- **Assignments.** Values with no letters (dates such as `TOKEN_EXPIRY=2026-09-01`) no longer count as secrets.
- **Redaction markers.** `[REDACTED:...]` was itself matching the password-in-URL rule on a rescan; it is now excluded, so a redacted store rescans clean.
- **Guard hook.** 14 cases checked. It no longer prompts for `.env.example`, `*.pub` public keys or `cp .env.example .env`, and still asks for `.env`, private SSH keys, `secrets.yml`, `printenv` and `gh auth token`.

Synthetic end-to-end check: transcripts seeded with fake AWS, GitHub, Anthropic and database-URL secrets were scanned (all found), redacted with `--apply` (every line still valid JSON), and rescanned (0 findings).

## Tests

```bash
python3 -m unittest discover -s tests
```

## Limits

Pattern matching catches known key formats and obvious assignments. It will miss free-form secrets ("the password is hunter2") and personal data like names or addresses. Treat a clean report as "no known patterns", not "nothing sensitive".
