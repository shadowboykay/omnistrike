"""waf_detect — WAF fingerprint via headers, cookies, response body markers"""
from core.http import HttpClient

SIGNATURES = {
    "Cloudflare":  ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
    "Akamai":      ["akamai", "ak-bmsc", "akamai-ghost"],
    "Imperva":     ["imperva", "incap_ses", "visid_incap", "x-iinfo"],
    "F5 BIG-IP":   ["bigip", "f5", "ts01", "x-wa-info"],
    "Sucuri":      ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
    "AWS WAF":     ["awselb", "x-amzn-requestid", "aws-waf"],
    "Fastly":      ["fastly", "x-served-by", "x-fastly"],
    "Cloudfront":  ["cloudfront", "x-amz-cf-id", "x-amz-cf-pop"],
    "ModSecurity": ["mod_security", "modsecurity", "owasp_crs"],
    "Wordfence":   ["wordfence", "wfvt_"],
}

class WafDetect:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        r = http.get(session.target, params={"omni_probe":"<script>alert(1)</script>' OR 1=1--"})
        if not r:
            print("[waf] no response"); return {"waf": None}
        blob = (str(r.headers) + " " + r.text[:5000]).lower()
        found = []
        for name, keys in SIGNATURES.items():
            if any(k.lower() in blob for k in keys):
                found.append(name)
        # blocking heuristic
        if r.status_code in (403, 406, 429, 503):
            found.append(f"blocking_{r.status_code}")
        if found:
            print(f"[waf] detected: {', '.join(found)}")
            logger.finding("waf", "info", ", ".join(found))
        else:
            print("[waf] no waf signature")
        return {"waf": found, "status": r.status_code, "server": r.headers.get("Server","")}
