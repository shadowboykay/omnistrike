"""payload_lab — interactive payload selection by context + WAF + target type"""
from core.payload_source import get_payloads, detect_waf
from core.http import HttpClient
import time


CONTEXT_PROMPTS = {
    "1": ("sql",        "SQL injection (SELECT/WHERE)"),
    "2": ("html_body",  "XSS in HTML body"),
    "3": ("path",       "Path traversal / LFI"),
    "4": ("cmd",        "Command injection"),
    "5": ("template",   "SSTI ({{7*7}})"),
    "6": ("xml",        "XXE (XML parser)"),
    "7": ("ssrf",       "SSRF (URL fetch)"),
    "8": ("ldap",       "LDAP filter injection"),
    "9": ("nosql",      "NoSQL (MongoDB)"),
    "10": ("crlf",      "CRLF injection"),
    "11": ("redirect",  "Open redirect"),
    "12": ("csti",      "Client-side template injection"),
    "13": ("saml",      "SAML injection"),
    "14": ("oauth",     "OAuth misconfig"),
    "15": ("deser",     "Deserialization"),
}


class PayloadLab:
    def run(self, session, logger):
        print(f"[payload_lab] target: {session.target}")
        print()

        # detect WAF from session
        waf = detect_waf(session)
        print(f"[payload_lab] WAF detected: {waf or 'none'}")

        print()
        print("=" * 60)
        print("  PAYLOAD LAB — выбери контекст")
        print("=" * 60)
        for k, (ctx, desc) in CONTEXT_PROMPTS.items():
            print(f"  {k:3s}. {desc}")
        print()

        # if --extra context=X — use it, else list all
        selected = None
        for x in session.extra:
            if x.startswith("context="):
                selected = x.split("=", 1)[1]

        if not selected:
            print("[payload_lab] передай контекст через --extra context=sql")
            print("[payload_lab] доступные контексты:")
            for k, (ctx, desc) in CONTEXT_PROMPTS.items():
                n = len(get_payloads(ctx, waf=waf))
                print(f"  {ctx:12s} {n:4d} payloads ({desc})")
            return {"contexts": [c for _, c in CONTEXT_PROMPTS.values()]}

        # find context key
        ctx = None
        for k, (c, _) in CONTEXT_PROMPTS.items():
            if c == selected:
                ctx = c
                break

        if not ctx:
            print(f"[payload_lab] unknown context: {selected}")
            return {"error": "unknown context"}

        payloads = get_payloads(ctx, waf=waf)
        print(f"\n[payload_lab] context: {ctx}")
        print(f"[payload_lab] payloads: {len(payloads)}")
        print()

        # show top 20 with explanations
        print("Топ-20 payload'ов (по типу атаки):")
        print("-" * 60)
        for i, p in enumerate(payloads[:20], 1):
            # add explanation
            expl = self._explain(p, ctx)
            print(f"  {i:2d}. {p[:60]}")
            if expl:
                print(f"      → {expl}")
        print()

        if len(payloads) > 20:
            print(f"  ... и ещё {len(payloads) - 20} payloads")
            print()

        # test mode
        test = any(x == "test=1" for x in session.extra)
        if test:
            print("[payload_lab] TEST MODE — проверка payload'ов на target")
            http = HttpClient(session, logger)
            base = http.get(session.target)
            if not base:
                print("  ✗ target unreachable")
                return {"payloads": len(payloads), "tested": 0}

            base_code = base.status_code
            base_len = len(base.content)
            findings = []

            for p in payloads[:30]:
                r = http.get(session.target, params={"test": p})
                if not r:
                    continue
                diff = abs(len(r.content) - base_len)
                if r.status_code != base_code or diff > 200:
                    print(f"  + DIFF {r.status_code} {len(r.content)}b: {p[:50]}")
                    findings.append({"payload": p, "code": r.status_code, "diff": diff})
                    logger.finding("payload_lab_hit", "medium",
                                   f"{p[:60]} -> {r.status_code}")
                time.sleep(0.3)

            print(f"\n[payload_lab] tested: 30, findings: {len(findings)}")
            return {"context": ctx, "tested": 30, "findings": findings}

        return {"context": ctx, "payloads": len(payloads), "sample": payloads[:20]}

    def _explain(self, payload, context):
        """Explain what a payload does."""
        p = payload.lower()
        if context == "sql":
            if "union" in p: return "UNION-based extraction"
            if "sleep" in p or "waitfor" in p: return "time-based blind"
            if "' or 1=1" in p: return "boolean auth bypass"
            if "' or '" in p: return "string concat bypass"
            if "information_schema" in p: return "schema enumeration"
        if context == "html_body":
            if "<script" in p: return "classic script tag"
            if "onerror" in p: return "img/onerror handler"
            if "onload" in p: return "onload handler"
            if "svg" in p: return "SVG-based"
            if "iframe" in p: return "iframe injection"
        if context == "path":
            if "etc/passwd" in p: return "read unix passwd"
            if "....//" in p: return "double-dot bypass"
            if "%2e" in p: return "url-encoded dots"
            if "php://" in p: return "PHP filter wrapper"
        if context == "cmd":
            if ";" in p: return "command separator"
            if "|" in p: return "pipe"
            if "`" in p: return "backtick exec"
            if "$(" in p: return "subshell"
        if context == "template":
            if "7*7" in p: return "math evaluation test"
            if "config" in p: return "config access"
            if "__class__" in p: return "python class chain"
        if context == "xml":
            if "ENTITY" in p: return "external entity"
            if "SYSTEM" in p: return "system file read"
            if "file://" in p: return "file scheme"
        if context == "ssrf":
            if "169.254" in p: return "AWS metadata"
            if "metadata.google" in p: return "GCP metadata"
            if "127.0.0.1" in p: return "localhost"
            if "0x7f" in p: return "hex-encoded localhost"
        return None
