"""waf_detect v3 — passive signatures + active behavioral WAF detection."""
import time
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
from core.http import HttpClient
from core.verify import confidence, is_signal


WAF_HEADERS = {
    "Cloudflare":  ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status", "cf-mitigated"],
    "Akamai":      ["akamai", "akamaighost", "x-akamai-transformed", "akamai-grn"],
    "AWS WAF":     ["x-amzn-waf-action", "awselb", "x-amz-cf-id", "x-amzn-requestid"],
    "Imperva":     ["imperva", "incap_ses", "visid_incap", "x-iinfo", "incapsula"],
    "Sucuri":      ["sucuri", "x-sucuri-id", "x-sucuri-cache", "cloudproxy"],
    "Fastly":      ["fastly", "x-served-by", "x-fastly", "fastly-io-info"],
    "F5 BIG-IP":   ["bigip", "big-ip", "x-wa-info"],
    "Barracuda":   ["barracuda", "barra_counter_session"],
    "FortiWeb":    ["fortiweb", "fortiwafsid", "fortigate"],
    "Wallarm":     ["wallarm", "x-wallarm-"],
    "Reblaze":     ["reblaze", "rbzid", "rbzsessionid"],
    "ModSecurity": ["mod_security", "modsecurity", "noyb"],
}


CHALLENGE_MARKERS = [
    "__cf_chl_", "cf_chl_opt", "cf-please-wait",
    "checking your browser", "just a moment",
    "awswaf", "aws-waf-token",
    "incapsula incident", "incident id",
    "captcha", "recaptcha", "hcaptcha", "turnstile",
    "please verify", "suspicious activity", "unusual traffic",
]


def _find_waf_in_headers(headers):
    hdrs_low = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
    hdrs_str = " ".join(hdrs_low.keys()) + " " + " ".join(str(v) for v in hdrs_low.values())
    detected = []
    for waf, sigs in WAF_HEADERS.items():
        for sig in sigs:
            if sig in hdrs_str:
                detected.append((waf, sig))
                break
    return detected


def _find_challenge(body):
    if not body:
        return None
    body_low = body.lower()[:5000]
    for marker in CHALLENGE_MARKERS:
        if marker in body_low:
            return marker
    return None


PROBES = [
    ("sqli_visible",   chr(39) + " OR 1=1-- -"),
    ("sqli_union",     chr(39) + " UNION SELECT NULL-- -"),
    ("xss_script",     "<script>alert(1)</script>"),
    ("path_traversal", "../../../../etc/passwd"),
    ("cmd_injection",  ";cat /etc/passwd"),
    ("log4shell",      "${jndi:ldap://omni-canary.invalid/a}"),
    ("xml_entity",     "<!DOCTYPE x SYSTEM 'file:///etc/passwd'>"),
    ("crlf",           "%0d%0aX-Omni-Injected:1"),
]


class WafDetect:
    def run(self, session, logger):
        base_url = session.target
        http = HttpClient(session, logger)

        print("[waf v3] target: " + base_url)

        try:
            t0 = time.time()
            r_base = http.get(base_url)
            baseline_time = time.time() - t0
        except Exception:
            print("[waf v3] baseline failed")
            return {"waf": [], "status": 0}

        if not r_base:
            return {"waf": [], "status": 0}

        base_status = r_base.status_code
        base_headers = dict(r_base.headers)
        base_body = r_base.text or ""

        print("[waf v3] baseline: " + str(base_status) + " " + str(round(baseline_time, 2)) + "s")

        passive_hits = _find_waf_in_headers(base_headers)
        for waf_name, sig in passive_hits:
            print("[waf v3] passive: " + waf_name + " (" + sig + ")")

        challenge = _find_challenge(base_body)
        if challenge:
            print("[waf v3] challenge in baseline: " + challenge)

        print()
        print("[waf v3] active probes:")

        u = urlparse(base_url)
        base_q = parse_qs(u.query)

        blocked = []
        probe_results = []

        for name, payload in PROBES:
            q = dict(base_q)
            q["omni_probe"] = [payload]
            probe_url = urlunparse(u._replace(query=urlencode(q, doseq=True)))
            try:
                t0 = time.time()
                r = http.get(probe_url, allow_redirects=False)
                dt = time.time() - t0
            except Exception:
                continue
            if not r:
                continue

            status = r.status_code
            delay_delta = dt - baseline_time
            is_block = status in (403, 406, 429, 501, 502, 503) or status >= 500
            body_challenge = _find_challenge(r.text or "")
            active_headers = _find_waf_in_headers(dict(r.headers))

            if is_block or body_challenge or active_headers or delay_delta > 0.5:
                probe_results.append({
                    "probe": name,
                    "status": status,
                    "delay_delta": round(delay_delta, 2),
                    "challenge": body_challenge,
                    "waf_headers": [w[0] for w in active_headers],
                })
                if is_block:
                    blocked.append(name)
                marker = "BLOCK" if is_block else "     "
                print("  [" + marker + "] " + name + ": " + str(status) + " delay+=" + str(round(delay_delta, 2)) + "s")

        print()
        print("[waf v3] rate-limit probe (10 burst)")
        rate_blocked = 0
        for i in range(10):
            try:
                rr = http.get(base_url)
            except Exception:
                continue
            if rr and rr.status_code == 429:
                rate_blocked += 1
        print("  429 responses: " + str(rate_blocked) + "/10")

        print()
        print("[waf v3] verdict:")

        waf_type = None
        if passive_hits:
            waf_type = passive_hits[0][0]
        elif probe_results:
            for pr in probe_results:
                if pr.get("waf_headers"):
                    waf_type = pr["waf_headers"][0]
                    break

        findings = []
        conf_strength = 0.5
        if passive_hits:
            conf_strength = 0.95
        elif blocked:
            conf_strength = 0.85
        elif rate_blocked >= 3:
            conf_strength = 0.75
        elif challenge:
            conf_strength = 0.9

        if conf_strength > 0.5:
            conf = confidence(conf_strength, 1.0)
            if is_signal(conf, floor=0.55, module="waf_detect"):
                findings.append({
                    "type": "waf_detected",
                    "severity": "info",
                    "waf": waf_type or "unknown",
                    "passive_hits": len(passive_hits),
                    "blocked_probes": blocked,
                    "challenge": challenge,
                    "rate_blocked": rate_blocked,
                    "confidence": conf,
                })
                print("  WAF detected: " + str(waf_type or "unknown") + " confidence=" + str(int(conf * 100)) + "%")
                logger.finding("waf_detect", "info", "waf=" + str(waf_type))
        else:
            print("  no WAF behavior detected")
            logger.finding("waf_detect", "info", "no waf behavior")

        recommendation = None
        if waf_type == "Cloudflare":
            recommendation = "cf-connecting-ip spoof + case_mix + whitespace_comment"
        elif waf_type == "Akamai":
            recommendation = "x-akamai spoof + retry-after delay + triple_encode"
        elif waf_type == "AWS WAF":
            recommendation = "chunked + sql_comment_split + rate pacing"
        elif waf_type == "Imperva":
            recommendation = "X-Forwarded-For + Referer chain + overlong_utf8"
        elif waf_type == "ModSecurity":
            recommendation = "double_encode + sql_comment_split + case_mix"
        elif waf_type == "Sucuri":
            recommendation = "x-sucuri-id spoof + html_decimal"
        elif blocked:
            recommendation = "chain mutations (depth=2) from core.waf_bypass"

        if recommendation:
            print()
            print("  recommended bypass: " + recommendation)

        print()
        print("[waf v3] findings: " + str(len(findings)))
        return {
            "waf": [w for w, _ in passive_hits],
            "waf_type": waf_type,
            "blocked_probes": blocked,
            "challenge": challenge,
            "rate_blocked": rate_blocked,
            "recommendation": recommendation,
            "findings": findings,
        }
