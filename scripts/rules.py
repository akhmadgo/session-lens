"""Secret / PII detection rules shared by the scanner, redactor and guard hook.

Stdlib only. Every rule returns the matched secret value so callers can mask,
hash or replace it. Raw values never leave this process.
"""
import hashlib
import re

# (id, label, severity, pattern, group-with-the-secret)
RULES = [
    ("private_key", "Private key block", "critical",
     re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----[\s\S]{20,}?-----END (?:[A-Z]+ )*PRIVATE KEY-----"), 0),
    ("anthropic_key", "Anthropic API key", "critical",
     re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"), 0),
    ("openai_key", "OpenAI API key", "critical",
     re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}"), 0),
    ("aws_access_key", "AWS access key ID", "critical",
     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    ("aws_secret", "AWS secret access key", "critical",
     re.compile(r"(?i)aws_secret_access_key[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})"), 1),
    ("github_token", "GitHub token", "critical",
     re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})"), 0),
    ("gitlab_token", "GitLab token", "critical",
     re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}"), 0),
    ("slack_token", "Slack token", "critical",
     re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), 0),
    ("stripe_key", "Stripe live key", "critical",
     re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}"), 0),
    ("google_api_key", "Google API key", "high",
     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 0),
    ("npm_token", "npm token", "high",
     re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), 0),
    ("huggingface_token", "Hugging Face token", "high",
     re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"), 0),
    ("jwt", "JSON Web Token", "high",
     re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), 0),
    ("url_credentials", "Password inside a URL", "high",
     re.compile(r"\b[a-z][a-z0-9+.\-]{1,20}://[^\s:/@\"']{1,64}:([^\s@/\"']{3,128})@[^\s/\"']+"), 1),
    ("secret_assignment", "Secret-looking assignment", "medium",
     re.compile(r"(?i)\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*)[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9/+_\-.!@#$%^&*]{12,})"), 2),
    ("credit_card", "Payment card number", "high",
     re.compile(r"(?<![\d.:\-=/#?&_])(?:4\d{3}|5[1-5]\d{2}|2[2-7]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))(?:[ -]?\d){9,15}(?![\d.:-])"), 0),
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2}

_PLACEHOLDER = re.compile(
    r"(?i)^(?:x+|\*+|\.+|<.*>|\$\{?.*|your[_-].*|example.*|changeme|placeholder.*|"
    r"process\.env.*|os\.environ.*|env\(.*|none|null|undefined|true|false|redacted.*|\[redacted:.*)$"
)


def _luhn(digits):
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


# Assignments whose value is not a secret: token counters (max_tokens = 4096,
# total_tokens = event.usage...), dotted code expressions, and ISO timestamps.
_COUNTER_KEY = re.compile(r"(?i)(?:tokens|token_?(?:count|limit|usage|budget))$")
_CODE_EXPR = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$")
_ISO_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[T ]|$)")


def _entropy_ok(value):
    # Reject values that are all one character class and short, e.g. "password123"
    # is still flagged, but "aaaaaaaaaaaa" or "____________" are not.
    return len(set(value)) >= 6


def find(text):
    """Yield (rule_id, label, severity, value, start, end) for each finding in text."""
    if not text or len(text) < 8:
        return
    seen_spans = []
    for rid, label, sev, pat, grp in RULES:
        for m in pat.finditer(text):
            value = m.group(grp)
            start, end = m.span(grp)
            if any(s <= start < e for s, e in seen_spans):
                continue  # already covered by a more specific rule
            if rid == "credit_card":
                digits = re.sub(r"\D", "", value)
                if len(digits) not in (15, 16, 19) or not _luhn(digits) or len(set(digits)) < 4:
                    continue
            if rid in ("secret_assignment", "url_credentials"):
                if _PLACEHOLDER.match(value) or not _entropy_ok(value) or not re.search(r"[A-Za-z]", value):
                    continue
            if rid == "secret_assignment":
                if _COUNTER_KEY.search(m.group(1)) or _CODE_EXPR.match(value) or _ISO_TIME.match(value):
                    continue
            seen_spans.append((start, end))
            yield rid, label, sev, value, start, end


def mask(value):
    v = value.replace("\n", " ")
    if len(v) <= 8:
        return "*" * len(v)
    return v[:4] + "…" + "*" * 6 + "…" + v[-2:] if len(v) > 24 else v[:3] + "*" * 6


def fingerprint(value):
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def redact(text):
    """Return (new_text, n_replacements)."""
    hits = sorted(find(text), key=lambda h: h[4], reverse=True)
    for rid, _, _, _, start, end in hits:
        text = text[:start] + f"[REDACTED:{rid}]" + text[end:]
    return text, len(hits)
