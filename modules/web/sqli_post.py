"""sqli_post — SQLi scanner for POST forms (auto-discover fields, test injections)"""
import time
from urllib.parse import urlparse
from core.http import HttpClient
from core.payloads import get

ERROR_MARKERS = [
    "sql syntax","mysql_fetch","ora-","postgresql","sqlstate","unclosed quotation",
    "quoted string not properly terminated","syntax error","odbc sql",
    "microsoft ole db","jdbc","java.sql.SQLException","invalid column",
]

# baseline indicators for login success
SUCCESS_MARKERS = ["welcome","logout","sign out","main.jsp","dashboard","account summary",
                   "balance","my account","administrator"]


class SqliPost:
    def run(self, session, logger):
        target = session.target
        # POST body: key1=val1&key2=val2 from --extra post=... or from url ?a=b&c=d
        u = urlparse(target)
        post_data = {}
        for x in session.extra:
            if x.startswith("post="):
                for pair in x[5:].split("&"):
                    k, _, v = pair.partition("=")
                    post_data[k] = v
        if not post_data:
            # fallback to url query
            from urllib.parse import parse_qs
            q = parse_qs(u.query)
            post_data = {k: v[0] for k, v in q.items()}
        if not post_data:
            print("[sqli_post] no POST data — use --extra post='uid=1&passw=1'")
            return {}

        post_url = target.split("?")[0]
        http = HttpClient(session, logger)

        print(f"[sqli_post] url: {post_url}")
        print(f"[sqli_post] fields: {list(post_data.keys())}")
        print(f"[sqli_post] ----------")

        # baseline
        base = http.post(post_url, data=post_data, label="baseline")
        base_len = len(base.content) if base else 0
        base_has_success = any(m in base.text.lower() for m in SUCCESS_MARKERS) if base else False
        print(f"[baseline] code={base.status_code if base else '?'} len={base_len} success_marker={base_has_success}")

        error_payloads = get("sqli", limit=40, mutate_by=0)
        findings = []

        for field in post_data:
            print(f"\n[field] '{field}'")
            for p in error_payloads:
                test = dict(post_data); test[field] = p
                r = http.post(post_url, data=test, label=f"{field}={p[:30]}")
                if not r:
                    continue
                low = r.text.lower()
                hit = next((m for m in ERROR_MARKERS if m in low), None)
                if hit:
                    print(f"      ✓ SQL ERROR: {hit}")
                    findings.append({"field":field,"payload":p,"type":"error","marker":hit})
                    logger.finding("sqli_post_error","high",f"{field}={p[:60]} marker={hit}")
                    continue
                # success-marker change
                has_success = any(m in low for m in SUCCESS_MARKERS)
                if has_success and not base_has_success:
                    print(f"      ✓ BYPASS — success marker appeared")
                    findings.append({"field":field,"payload":p,"type":"auth_bypass"})
                    logger.finding("sqli_post_bypass","critical",f"{field}={p[:60]} bypasses login")
                # big length diff
                if abs(len(r.content) - base_len) > 500:
                    print(f"      ✓ DIFF {len(r.content)-base_len:+d}b")
                    findings.append({"field":field,"payload":p,"type":"diff","delta":len(r.content)-base_len})
                    logger.finding("sqli_post_diff","medium",f"{field}={p[:60]} diff={len(r.content)-base_len}")

        print(f"\n[sqli_post] total findings: {len(findings)}")
        return {"findings": findings}
