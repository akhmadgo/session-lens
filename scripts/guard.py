#!/usr/bin/env python3
"""Session Lens guard: a Claude Code hook that keeps secrets out of transcripts.

UserPromptSubmit  blocks a prompt that contains a critical/high secret (the
                  prompt is discarded before it is written to the transcript).
                  Add  #allow-secret  anywhere in the prompt to send it anyway.
PreToolUse        asks you before Claude reads a credential file (.env, SSH keys,
                  cloud credentials...) or runs a command that would print one,
                  because the full output is stored in the transcript.

Set SESSION_LENS_GUARD=off to disable. Never fails closed: any internal error
lets the action through.
"""
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

SENSITIVE_PATH = re.compile(
    r"""(?ix)(?:^|[/\\\s'"=])(
        \.env(?!\.(?:example|sample|template|dist|defaults)\b)(?:\.[\w.-]+)?
      | id_(?:rsa|dsa|ecdsa|ed25519)(?!\.pub)
      | [\w.-]+\.(?:pem|key|p12|pfx|keystore|jks)
      | \.(?:npmrc|pypirc|netrc|git-credentials|pgpass)
      | \.aws/credentials | \.docker/config\.json | \.kube/config
      | \.config/gcloud/[\w./-]+ | \.ssh/(?!known_hosts|config\b|[\w.-]+\.pub\b|authorized_keys)[\w.-]+
      | credentials\.json | service[-_]?account[\w.-]*\.json
      | secrets?\.(?:ya?ml|json|toml|env)
    )(?=$|[\s'";|&)>])""")

READERS = r"(?:cat|less|more|head|tail|bat|nl|strings|xxd|od|base64|grep|rg|awk|sed|curl\s+.*-d\s*@)"
DUMPERS = re.compile(
    r"""(?x)(?:^|[;&|]\s*|\$\(\s*)(?:
        printenv\b | env\s*(?:$|[|;>]) | set\s*(?:$|\|) | export\s+-p
      | echo\s+[^|;]*\$\{?\w*(?:TOKEN|SECRET|KEY|PASSWORD|PASS)\w*
      | security\s+find-(?:generic|internet)-password\b.*-w
      | gcloud\s+auth\s+print-(?:access|identity)-token
      | aws\s+configure\s+get | gh\s+auth\s+token | op\s+read\b
    )""", re.I)


def ask(reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "ask",
        "permissionDecisionReason": reason,
    }}))


def pre_tool_use(event):
    tool, inp = event.get("tool_name", ""), event.get("tool_input") or {}
    if tool in ("Read", "Edit", "Write", "NotebookEdit", "Grep", "Glob"):
        target = " " + str(inp.get("file_path") or inp.get("notebook_path") or inp.get("path") or "")
        if tool == "Grep" and inp.get("glob"):
            target += " " + str(inp["glob"])
        m = SENSITIVE_PATH.search(target)
        if m and tool in ("Read", "Grep"):
            ask(f"Session Lens: {m.group(1)} looks like a credential file. Its contents would be "
                f"stored permanently in this session's transcript on disk. Allow?")
    elif tool == "Bash":
        cmd = str(inp.get("command", ""))
        m = SENSITIVE_PATH.search(cmd)
        if m and re.search(rf"(?:^|[;&|(\s]){READERS}\b", cmd):
            ask(f"Session Lens: this command prints {m.group(1)}, which looks like a credential file. "
                f"The output would be stored in this session's transcript. Allow?")
        elif DUMPERS.search(cmd):
            ask("Session Lens: this command prints environment variables or credentials. "
                "The output would be stored in this session's transcript. Allow?")


def user_prompt_submit(event):
    import rules
    prompt = event.get("prompt") or ""
    if "#allow-secret" in prompt:
        return
    hits = [h for h in rules.find(prompt) if h[2] in ("critical", "high")]
    if not hits:
        return
    kinds = ", ".join(sorted({f"{h[1]} ({rules.mask(h[3])})" for h in hits}))
    print(json.dumps({
        "decision": "block",
        "reason": (f"Session Lens blocked this prompt: it contains {kinds}. Prompts are saved to "
                   f"~/.claude/projects/ and ~/.claude/history.jsonl in plain text. Reference the "
                   f"secret by env var name instead, or add #allow-secret to send it anyway."),
    }))


def main():
    if os.environ.get("SESSION_LENS_GUARD", "").lower() in ("off", "0", "false"):
        return
    try:
        event = json.load(sys.stdin)
        name = event.get("hook_event_name")
        if name == "PreToolUse":
            pre_tool_use(event)
        elif name == "UserPromptSubmit":
            user_prompt_submit(event)
    except Exception:  # never break the user's session because of the guard
        pass


if __name__ == "__main__":
    main()
