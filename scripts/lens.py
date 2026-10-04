#!/usr/bin/env python3
"""Session Lens: see what Claude Code keeps on your disk, and clean it up.

    lens.py scan   [--out PATH] [--no-open]    build the local HTML report, print a masked JSON summary
    lens.py redact [--apply] [--include-active] replace detected secrets with [REDACTED:<rule>]

Stdlib only. Reads ~/.claude (or $CLAUDE_CONFIG_DIR). Makes no network calls.
Secret values are never printed or written to the report; only masked previews
and short SHA-256 fingerprints.
"""
import argparse
import html
import json
import os
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rules  # noqa: E402

HOME = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")
OUT_DIR = HOME / "session-lens"
ACTIVE_WINDOW_S = 120
DEFAULT_RETENTION_DAYS = 30

# Local stores besides transcripts, with a plain-language description.
STORES = [
    ("projects", "Session transcripts", "Every prompt, every reply (including thinking), every tool call and its full output: file contents Claude read, command output, fetched pages."),
    ("history.jsonl", "Prompt history", "Each prompt you typed, plus pasted content, used for up-arrow recall."),
    ("file-history", "File checkpoints", "Copies of files taken before Claude edited them, used for rewind."),
    ("paste-cache", "Paste cache", "Large pasted blocks stored outside the transcript."),
    ("shell-snapshots", "Shell snapshots", "Your shell's functions, aliases and options captured so Bash tool calls behave like your terminal."),
    ("todos", "Todo lists", "Task lists from sessions."),
    ("debug", "Debug logs", "Diagnostic logs, if debug mode was used."),
    ("telemetry", "Telemetry queue", "Usage events waiting to be sent."),
    ("backups", "Config backups", "Backups of Claude Code's own config files."),
]


# ---------------------------------------------------------------- helpers

def iso(ts):
    if not ts:
        return ""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return ts[:16]


def du(path):
    if path.is_file():
        return path.stat().st_size, 1
    size = n = 0
    for p in path.rglob("*"):
        if p.is_file():
            try:
                size += p.stat().st_size
                n += 1
            except OSError:
                pass
    return size, n


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def walk_strings(obj, path=()):
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_strings(v, path + (i,))


def where(record, path):
    kind = record.get("type")
    keys = {p for p in path if isinstance(p, str)}
    if "toolUseResult" in keys:
        return "tool output"
    if kind == "user":
        content = record.get("message", {}).get("content")
        if isinstance(content, list) and len(path) > 2 and isinstance(path[2], int):
            part = content[path[2]] if path[2] < len(content) else {}
            if isinstance(part, dict) and part.get("type") == "tool_result":
                return "tool output"
        return "your prompt"
    if kind == "assistant":
        content = record.get("message", {}).get("content")
        if isinstance(content, list) and len(path) > 2 and isinstance(path[2], int) and path[2] < len(content):
            t = content[path[2]].get("type") if isinstance(content[path[2]], dict) else None
            return {"tool_use": "tool input", "thinking": "Claude's thinking"}.get(t, "Claude's reply")
        return "Claude's reply"
    return "session metadata"


def load_settings():
    merged = {}
    for name in ("settings.json", "settings.local.json"):
        try:
            merged.update(json.loads((HOME / name).read_text()))
        except (OSError, ValueError):
            pass
    return merged


# ---------------------------------------------------------------- scanning

class Findings:
    def __init__(self):
        self.by_fp = {}

    def add(self, rid, label, sev, value, location, kind, session):
        fp = rules.fingerprint(value)
        f = self.by_fp.get(fp)
        if f is None:
            f = self.by_fp[fp] = {
                "fingerprint": fp, "rule": rid, "label": label, "severity": sev,
                "masked": rules.mask(value), "count": 0, "where": Counter(),
                "sessions": set(), "files": set(),
            }
        f["count"] += 1
        f["where"][kind] += 1
        f["files"].add(location)
        if session:
            f["sessions"].add(session)

    def sorted(self):
        return sorted(self.by_fp.values(),
                      key=lambda f: (rules.SEVERITY_ORDER[f["severity"]], -f["count"]))


def scan_transcript(path, findings):
    s = {
        "file": str(path), "bytes": path.stat().st_size, "session": path.stem,
        "subagent": "subagents" in path.parts, "title": "", "first_prompt": "",
        "cwd": "", "branch": "", "start": "", "end": "", "prompts": 0,
        "tools": Counter(), "read": [], "changed": [], "commands": [],
        "web": [], "mcp": Counter(), "models": Counter(), "secrets": 0,
    }
    try:
        fh = path.open(encoding="utf-8", errors="replace")
    except OSError:
        return s
    with fh:
        for line in fh:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if not isinstance(r, dict):
                continue
            ts = r.get("timestamp")
            if ts:
                s["start"] = s["start"] or ts
                s["end"] = ts
            s["cwd"] = s["cwd"] or r.get("cwd", "")
            s["branch"] = s["branch"] or r.get("gitBranch", "")
            if r.get("type") == "custom-title" and r.get("customTitle"):
                s["title"] = r["customTitle"]
            msg = r.get("message") if isinstance(r.get("message"), dict) else {}
            content = msg.get("content")
            if r.get("type") == "user" and not r.get("isMeta"):
                text = content if isinstance(content, str) else " ".join(
                    c.get("text", "") for c in content or [] if isinstance(c, dict) and c.get("type") == "text")
                if text.strip() and not text.lstrip().startswith("<"):
                    s["prompts"] += 1
                    s["first_prompt"] = s["first_prompt"] or text.strip()
            if r.get("type") == "assistant":
                if msg.get("model"):
                    s["models"][msg["model"]] += 1
                for c in content if isinstance(content, list) else []:
                    if not isinstance(c, dict) or c.get("type") != "tool_use":
                        continue
                    name, inp = c.get("name", "?"), c.get("input") or {}
                    s["tools"][name] += 1
                    if name.startswith("mcp__"):
                        s["mcp"][name.split("__")[1]] += 1
                    fp = inp.get("file_path") or inp.get("notebook_path")
                    if name == "Read" and fp:
                        s["read"].append(fp)
                    elif name in ("Edit", "Write", "MultiEdit", "NotebookEdit") and fp:
                        s["changed"].append(fp)
                    elif name == "Bash" and inp.get("command"):
                        s["commands"].append(inp["command"])
                    elif name == "WebFetch" and inp.get("url"):
                        s["web"].append(inp["url"])
                    elif name == "WebSearch" and inp.get("query"):
                        s["web"].append("search: " + inp["query"])
            seen = set()
            for p, text in walk_strings(r):
                for rid, label, sev, value, _, _ in rules.find(text):
                    fp_ = rules.fingerprint(value)
                    if fp_ in seen:  # toolUseResult duplicates message content
                        continue
                    seen.add(fp_)
                    s["secrets"] += 1
                    findings.add(rid, label, sev, value, str(path), where(r, p), s["session"])
    return s


def scan_plain(path, findings, kind):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    for rid, label, sev, value, _, _ in rules.find(text):
        findings.add(rid, label, sev, value, str(path), kind, None)


def scan():
    findings = Findings()
    sessions = []
    projects = HOME / "projects"
    for p in sorted(projects.rglob("*.jsonl")) if projects.exists() else []:
        sessions.append(scan_transcript(p, findings))
    for p in sorted(projects.rglob("memory/*.md")) if projects.exists() else []:
        scan_plain(p, findings, "memory file")

    hist = HOME / "history.jsonl"
    if hist.exists():
        scan_plain(hist, findings, "prompt history")
    for sub, kind in (("file-history", "file checkpoint"), ("paste-cache", "paste cache"),
                      ("shell-snapshots", "shell snapshot"), ("todos", "todo list"), ("debug", "debug log")):
        d = HOME / sub
        if d.exists():
            for p in d.rglob("*"):
                if p.is_file() and p.stat().st_size < 20_000_000:
                    scan_plain(p, findings, kind)

    stores = []
    for name, label, desc in STORES:
        p = HOME / name
        if p.exists():
            size, n = du(p)
            stores.append({"path": str(p), "label": label, "desc": desc, "bytes": size, "files": n})

    settings = load_settings()
    retention = settings.get("cleanupPeriodDays", DEFAULT_RETENTION_DAYS)
    starts = [s["start"] for s in sessions if s["start"]]
    return {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "home": str(HOME),
        "retention_days": retention,
        "retention_set": "cleanupPeriodDays" in settings,
        "oldest": min(starts) if starts else "",
        "sessions": sessions,
        "stores": stores,
        "findings": findings.sorted(),
    }


# ---------------------------------------------------------------- report

CSS = """
:root{--bg:#fbfaf7;--panel:#fff;--ink:#1d1c1a;--muted:#6b6862;--line:#e6e2da;--accent:#c2562f;
--crit:#b42318;--crit-bg:#fdecea;--high:#b54708;--high-bg:#fef4e6;--med:#6b5b00;--med-bg:#fbf6dc;--ok:#1f7a4d;--ok-bg:#e8f5ee;
--mono:ui-monospace,SFMono-Regular,Menlo,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#181715;--panel:#211f1c;--ink:#ece9e3;--muted:#a19d95;--line:#35322d;--accent:#e07a52;
--crit:#ff8a7a;--crit-bg:#3a1d1a;--high:#f5b36b;--high-bg:#3a2a16;--med:#e6d27a;--med-bg:#33301a;--ok:#7fd3a5;--ok-bg:#16301f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:40px 0 12px}.sub{color:var(--muted);margin:0 0 24px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.tile b{display:block;font-size:24px;font-variant-numeric:tabular-nums}.tile span{color:var(--muted);font-size:13px}
.tile.bad b{color:var(--crit)}.tile.good b{color:var(--ok)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:600}
tr:last-child td{border-bottom:0}td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
code{font-family:var(--mono);font-size:13px}.muted{color:var(--muted)}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600}
.critical{color:var(--crit);background:var(--crit-bg)}.high{color:var(--high);background:var(--high-bg)}.medium{color:var(--med);background:var(--med-bg)}
.clean{color:var(--ok);background:var(--ok-bg)}
.wrap{overflow-x:auto}details{margin:0}summary{cursor:pointer}
.detail{padding:8px 0 4px;font-size:13px}.detail h4{margin:10px 0 4px;font-size:12px;text-transform:uppercase;color:var(--muted)}
.detail ul{margin:0;padding-left:18px;max-height:220px;overflow:auto}.detail li{font-family:var(--mono);word-break:break-all}
.note{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:8px;padding:12px 16px;margin:12px 0}
pre{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 12px;overflow-x:auto}
input[type=search]{width:100%;max-width:360px;padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--ink);margin-bottom:10px}
"""

JS = """
const q=document.getElementById('q');q&&q.addEventListener('input',()=>{const v=q.value.toLowerCase();
document.querySelectorAll('#sessions tbody tr').forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(v)?'':'none'})});
"""


def e(x):
    return html.escape(str(x), quote=True)


def lst(title, items, limit=200):
    if not items:
        return ""
    items = list(dict.fromkeys(items))
    more = f"<li class='muted'>…and {len(items) - limit} more</li>" if len(items) > limit else ""
    return f"<h4>{e(title)} ({len(items)})</h4><ul>" + "".join(
        f"<li>{e(i[:300])}</li>" for i in items[:limit]) + more + "</ul>"


def render(data):
    sessions = sorted(data["sessions"], key=lambda s: s["end"], reverse=True)
    findings = data["findings"]
    total_bytes = sum(s["bytes"] for s in sessions)
    crit = sum(1 for f in findings if f["severity"] == "critical")
    files_read = {f for s in sessions for f in s["read"]}
    cmds = sum(len(s["commands"]) for s in sessions)
    oldest_days = ""
    if data["oldest"]:
        try:
            dt = datetime.fromisoformat(data["oldest"].replace("Z", "+00:00"))
            oldest_days = f"{(datetime.now(timezone.utc) - dt).days} days"
        except ValueError:
            pass
    retention = data["retention_days"]
    sev_tile = "bad" if crit else ("good" if not findings else "")

    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<title>Session Lens</title><style>{CSS}</style></head><body><main>",
           "<h1>Session Lens</h1>",
           f"<p class='sub'>What Claude Code has stored in <code>{e(data['home'])}</code> on this machine. "
           f"Generated {e(iso(data['generated']))}. This report was built locally and never left your computer; secret values are masked.</p>",
           "<div class='tiles'>",
           f"<div class='tile'><b>{len([s for s in sessions if not s['subagent']])}</b><span>sessions on disk ({human(total_bytes)})</span></div>",
           f"<div class='tile'><b>{len(files_read)}</b><span>distinct files Claude read, contents kept in transcripts</span></div>",
           f"<div class='tile'><b>{cmds}</b><span>shell commands, with their output</span></div>",
           f"<div class='tile {sev_tile}'><b>{len(findings)}</b><span>distinct secrets found ({crit} critical)</span></div>",
           f"<div class='tile'><b>{e(oldest_days or '—')}</b><span>age of oldest transcript; auto-deleted after {e(retention)} days{'' if data['retention_set'] else ' (default)'}</span></div>",
           "</div>"]

    # Findings
    out.append("<h2>Secrets and sensitive values</h2>")
    if findings:
        out.append("<div class='note'>Each row is one distinct value, matched by fingerprint across every file. "
                   "“Where” shows how it got in: <b>tool output</b> usually means Claude read a <code>.env</code> or ran a command that printed it; "
                   "<b>your prompt</b> means it was pasted. Rotate anything critical: deleting the transcript does not un-leak a key.</div>")
        out.append("<div class='wrap'><table><thead><tr><th>Severity</th><th>Type</th><th>Masked value</th><th>Where</th>"
                   "<th class='num'>Seen</th><th class='num'>Sessions</th><th>Fingerprint</th></tr></thead><tbody>")
        for f in findings:
            wh = ", ".join(f"{k} ×{v}" for k, v in f["where"].most_common())
            out.append(f"<tr><td><span class='pill {f['severity']}'>{f['severity']}</span></td><td>{e(f['label'])}</td>"
                       f"<td><code>{e(f['masked'])}</code></td><td>{e(wh)}</td><td class='num'>{f['count']}</td>"
                       f"<td class='num'>{len(f['sessions'])}</td><td><code class='muted'>{f['fingerprint']}</code></td></tr>")
        out.append("</tbody></table></div>")
        out.append("<p>To scrub them from local files, ask Claude <i>“redact my session secrets”</i> or run:</p>"
                   "<pre><code>python3 &lt;plugin&gt;/scripts/lens.py redact          # dry run\n"
                   "python3 &lt;plugin&gt;/scripts/lens.py redact --apply</code></pre>")
    else:
        out.append("<p><span class='pill clean'>clean</span> No known secret patterns found.</p>")

    # Stores
    out.append("<h2>What is stored where</h2><div class='wrap'><table><thead><tr><th>Store</th><th>Contains</th>"
               "<th class='num'>Files</th><th class='num'>Size</th></tr></thead><tbody>")
    for st in data["stores"]:
        out.append(f"<tr><td><b>{e(st['label'])}</b><br><code class='muted'>{e(st['path'])}</code></td><td>{e(st['desc'])}</td>"
                   f"<td class='num'>{st['files']}</td><td class='num'>{human(st['bytes'])}</td></tr>")
    out.append("</tbody></table></div>")

    # Sessions
    out.append("<h2>Sessions</h2><input id='q' type='search' placeholder='Filter by project, title, file, command…'>"
               "<div class='wrap'><table id='sessions'><thead><tr><th>Session</th><th>Project</th><th>Last active</th>"
               "<th class='num'>Prompts</th><th class='num'>Tool calls</th><th class='num'>Secrets</th><th class='num'>Size</th></tr></thead><tbody>")
    for s in sessions:
        title = s["title"] or s["first_prompt"][:90] or s["session"]
        if s["subagent"]:
            title = "↳ subagent: " + title
        tools = ", ".join(f"{k} ×{v}" for k, v in s["tools"].most_common())
        detail = (f"<div class='detail'><div class='muted'>{e(s['file'])}</div>"
                  + (f"<h4>Tools</h4><div>{e(tools)}</div>" if tools else "")
                  + (f"<h4>MCP servers</h4><div>{e(', '.join(s['mcp']))}</div>" if s["mcp"] else "")
                  + lst("Files read", s["read"]) + lst("Files changed", s["changed"])
                  + lst("Commands run", s["commands"]) + lst("Web", s["web"]) + "</div>")
        sec = f"<span class='pill critical'>{s['secrets']}</span>" if s["secrets"] else "<span class='muted'>0</span>"
        out.append(f"<tr><td><details><summary>{e(title)}</summary>{detail}</details></td>"
                   f"<td><code>{e(s['cwd'] or '—')}</code>{'<br><span class=muted>' + e(s['branch']) + '</span>' if s['branch'] else ''}</td>"
                   f"<td class='num'>{e(iso(s['end']))}</td><td class='num'>{s['prompts']}</td>"
                   f"<td class='num'>{sum(s['tools'].values())}</td><td class='num'>{sec}</td><td class='num'>{human(s['bytes'])}</td></tr>")
    out.append("</tbody></table></div>")

    out.append("<h2>Reduce what gets kept</h2><div class='note'><ul>"
               f"<li>Shorten retention: set <code>\"cleanupPeriodDays\": 7</code> in <code>{e(data['home'])}/settings.json</code> "
               f"(currently {e(retention)}). Old sessions are removed when Claude Code starts.</li>"
               "<li>Keep secret files out of reach: add <code>\"deny\": [\"Read(./.env)\", \"Read(./.env.*)\", \"Read(./secrets/**)\"]</code> under <code>permissions</code>.</li>"
               "<li>The Session Lens guard hook blocks prompts containing keys and blocks reads of <code>.env</code>, SSH keys and credential files before they enter a transcript.</li>"
               "</ul></div>")
    out.append(f"<script>{JS}</script></main></body></html>")
    return "".join(out)


def summary(data, report_path):
    sessions = data["sessions"]
    return {
        "report": str(report_path),
        "sessions": len([s for s in sessions if not s["subagent"]]),
        "subagent_transcripts": len([s for s in sessions if s["subagent"]]),
        "transcript_bytes": sum(s["bytes"] for s in sessions),
        "oldest_transcript": data["oldest"],
        "retention_days": data["retention_days"],
        "retention_is_default": not data["retention_set"],
        "distinct_files_read": len({f for s in sessions for f in s["read"]}),
        "commands_run": sum(len(s["commands"]) for s in sessions),
        "mcp_servers_used": sorted({m for s in sessions for m in s["mcp"]}),
        "stores": [{k: st[k] for k in ("label", "path", "files", "bytes")} for st in data["stores"]],
        "findings": [{
            "severity": f["severity"], "type": f["label"], "masked": f["masked"],
            "fingerprint": f["fingerprint"], "seen": f["count"], "sessions": len(f["sessions"]),
            "where": dict(f["where"]),
        } for f in data["findings"]],
    }


def cmd_scan(args):
    data = scan()
    out = Path(args.out).expanduser() if args.out else OUT_DIR / "report.html"
    out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(render(data))
    print(json.dumps(summary(data, out), indent=2))
    if not args.no_open:
        opener = {"darwin": ["open"], "win32": ["cmd", "/c", "start", ""]}.get(sys.platform, ["xdg-open"])
        try:
            subprocess.Popen(opener + [str(out)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            pass


# ---------------------------------------------------------------- redact

def redact_obj(obj):
    n = 0
    if isinstance(obj, str):
        return rules.redact(obj)
    if isinstance(obj, dict):
        for k, v in obj.items():
            obj[k], c = redact_obj(v)
            n += c
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            obj[i], c = redact_obj(v)
            n += c
    return obj, n


def rewrite(path, new_text):
    mode = path.stat().st_mode & 0o777
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".lens-")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(new_text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def redact_file(path, apply):
    data = path.read_bytes()
    if b"\0" in data[:8192]:
        return 0  # binary file; leave untouched
    raw = data.decode("utf-8", errors="replace")
    total = 0
    if path.suffix == ".jsonl":
        lines = []
        for line in raw.splitlines(keepends=True):
            body = line.rstrip("\n")
            try:
                obj = json.loads(body)
            except ValueError:
                new, n = rules.redact(line)
                lines.append(new)
                total += n
                continue
            obj, n = redact_obj(obj)
            total += n
            lines.append(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n" if n else line)
        new_text = "".join(lines)
    else:
        new_text, total = rules.redact(raw)
    if total and apply:
        rewrite(path, new_text)
    return total


def cmd_redact(args):
    targets = []
    for sub in ("projects", "file-history", "paste-cache", "shell-snapshots", "todos", "debug"):
        d = HOME / sub
        if d.exists():
            targets += [p for p in d.rglob("*") if p.is_file()]
    if (HOME / "history.jsonl").exists():
        targets.append(HOME / "history.jsonl")

    now, results, skipped = time.time(), [], []
    for p in sorted(set(targets)):
        try:
            if p.stat().st_size > 50_000_000:
                continue
            if not args.include_active and now - p.stat().st_mtime < ACTIVE_WINDOW_S and p.suffix == ".jsonl":
                skipped.append(str(p))
                continue
            n = redact_file(p, args.apply)
        except (OSError, UnicodeError):
            continue
        if n:
            results.append({"file": str(p), "replacements": n})
    print(json.dumps({
        "mode": "applied" if args.apply else "dry-run",
        "files": len(results), "replacements": sum(r["replacements"] for r in results),
        "changed": results, "skipped_active": skipped,
        "note": None if args.apply else "Nothing was changed. Re-run with --apply to rewrite these files.",
    }, indent=2))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="build the HTML report")
    s.add_argument("--out")
    s.add_argument("--no-open", action="store_true")
    r = sub.add_parser("redact", help="replace secrets with [REDACTED:<rule>]")
    r.add_argument("--apply", action="store_true", help="rewrite files (default is a dry run)")
    r.add_argument("--include-active", action="store_true",
                   help=f"also rewrite transcripts modified in the last {ACTIVE_WINDOW_S}s")
    args = ap.parse_args()
    {"scan": cmd_scan, "redact": cmd_redact}[args.cmd](args)


if __name__ == "__main__":
    main()
