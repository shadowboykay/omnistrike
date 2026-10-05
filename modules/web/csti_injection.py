"""csti_injection v2 — Client-Side Template Injection."""
import secrets
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from core.verify import confidence, is_signal

FRAMEWORK_INDICATORS = {
    "angularjs": ["ng-app", "ng-controller", "ng-model", "data-ng-app", "angular.js", "angular.min.js"],
    "vue": ["v-app", "v-model", "v-if", "v-for", "vue.js", "vue.min.js"],
    "react": ["react.production.min.js", "react.development.js", "data-reactroot"],
    "handlebars": ["handlebars.js", "handlebars.min.js"],
    "mustache": ["mustache.js", "mustache.min.js"],
}

CSTI_PAYLOADS = [
    ("angular_math", "{{7*7}}", "angularjs"),
    ("angular_alt",  "${{7*7}}", "angularjs"),
    ("vue_math",     "{{7*7}}", "vue"),
    ("hb_math",      "{{7*7}}", "handlebars"),
    ("mustache_math","{{7*7}}", "mustache"),
]

UNIQUE_MARKER = "OMNI_CSTI_MARKER_" + secrets.token_hex(4)


def _fingerprint(body):
    body_low = (body or "").lower()
    found = set()
    for fw, indicators in FRAMEWORK_INDICATORS.items():
        for ind in indicators:
            if ind.lower() in body_low:
                found.add(fw)
                break
    return found


class CstiInjection:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        u = urlparse(target)
        params = parse_qs(u.query) or {"q": ["test"]}
        print("[csti v2] target: " + target)
        try:
            base_r = http.get(target)
            baseline_text = (base_r.text or "") if base_r else ""
        except Exception:
            baseline_text = ""
        frameworks = _fingerprint(baseline_text)
        print("[csti v2] frameworks: " + (str(frameworks) if frameworks else "(none)"))
        print("[csti v2] params: " + str(list(params.keys())))
        findings = []
        for name in params:
            print()
            print("[csti v2] param: " + name)
            for pname, payload, fw_hint in CSTI_PAYLOADS:
                q = {k: v[0] for k, v in params.items()}
                q[name] = payload
                test_url = urlunparse(u._replace(query=urlencode(q, doseq=True)))
                try:
                    r = http.get(test_url)
                except Exception:
                    continue
                if not r:
                    continue
                body = r.text or ""
                raw_reflection = payload in body
                if "7*7" in payload and "49" in body:
                    continue
                if not raw_reflection:
                    continue
                detected_fw = None
                if fw_hint and fw_hint in frameworks:
                    detected_fw = fw_hint
                elif frameworks:
                    for fw in frameworks:
                        if fw_hint is None or fw == fw_hint:
                            detected_fw = fw
                            break
                try:
                    r2 = http.get(test_url)
                except Exception:
                    r2 = None
                if not r2 or payload not in (r2.text or ""):
                    continue
                strength = 0.85 if detected_fw else 0.5
                conf = confidence(strength, 1.0)
                if not is_signal(conf, floor=0.55, module="csti"):
                    continue
                sev = "high" if detected_fw else "info"
                findings.append({
                    "type": "csti_confirmed" if detected_fw else "csti_possible",
                    "severity": sev,
                    "param": name,
                    "payload_name": pname,
                    "payload": payload,
                    "framework": detected_fw,
                    "confidence": conf,
                })
                print("  CSTI " + pname + " fw=" + str(detected_fw))
                logger.finding("csti", sev, name + "=" + pname)
                break
        print()
        print("[csti v2] findings: " + str(len(findings)))
        return {"findings": findings, "frameworks": list(frameworks)}
