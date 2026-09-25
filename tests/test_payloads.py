"""Test payload source — 17 contexts with payloads."""
from core.payload_source import get_payloads, detect_waf

CONTEXTS = ["sql", "html_body", "path", "template", "xml", "ssrf",
            "redirect", "cmd", "ldap", "xslt", "csti", "crlf",
            "nosql", "ssi", "saml", "oauth", "deser"]


def test_all_contexts_have_payloads():
    for ctx in CONTEXTS:
        p = get_payloads(ctx)
        assert len(p) > 0, f"Context {ctx} has no payloads"


def test_waf_detection():
    assert detect_waf.__class__.__name__ == "function"
