# core/probe.py — unified probe: baseline + inject + verify + auto-dump
import time
from core.http import HttpClient
from core.mutator import mutate_param as mutate


class Probe:
    """
    Unified vulnerability probe.
      - baseline comparison
      - payload injection
      - automatic mutation on block (via http.auto_mutate)
      - false-positive filter (raw-reflected vs encoded)
      - verify(): second independent check for any finding
      - auto_dump(): trigger dump module when injectable
      - severity: auto-escalate based on context
    """

    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        self.http = HttpClient(session, logger)
        self.baseline = None
        self.stats = {"requests": 0, "blocks": 0, "hits": 0, "mutations": 0, "verified": 0, "dumps": 0}

    # ---------- baseline ----------

    def baseline_probe(self, url, method="GET", data=None):
        r = self.http.get(url) if method == "GET" else self.http.post(url, data=data)
        if not r:
            return None
        self.baseline = {
            "code": r.status_code,
            "len": len(r.content),
            "text": r.text,
            "time": 0,
        }
        return self.baseline

    # ---------- inject ----------

    def inject(self, url_fn, payload, method="GET", data_fn=None,
               detect_markers=None, expect_code=None, allow_redirects=True):
        expect_code = expect_code or 200
        variants = mutate(payload, n=5, base_first=True)
        variants_tried = 0

        for variant in variants:
            variants_tried += 1
            self.stats["requests"] += 1

            t0 = time.time()
            if method == "GET":
                r = self.http.get(url_fn(variant), allow_redirects=allow_redirects)
            else:
                r = self.http.post(url_fn(variant), data=data_fn(variant) if data_fn else None,
                                   allow_redirects=allow_redirects)
            dt = time.time() - t0

            if not r:
                continue

            if r.status_code in (403, 406, 429, 503):
                self.stats["blocks"] += 1
                self.stats["mutations"] += 1
                continue

            if r.status_code != expect_code:
                continue

            # XSS-specific: raw reflection
            if variant in r.text and "<script" in variant.lower():
                if "&lt;script" in r.text or "&lt;" in r.text[:200]:
                    return {"hit": False, "reason": "reflected-encoded",
                            "payload": variant, "variants_tried": variants_tried}
                return {"hit": True, "reason": "raw-reflected",
                        "payload": variant, "variants_tried": variants_tried}

            # marker match
            if detect_markers:
                low = r.text.lower()
                for m in detect_markers:
                    if m.lower() in low:
                        self.stats["hits"] += 1
                        return {"hit": True, "reason": f"marker:{m}",
                                "payload": variant, "variants_tried": variants_tried,
                                "code": r.status_code, "response": r}

            # length diff (blind boolean)
            if self.baseline and abs(len(r.content) - self.baseline["len"]) > 200:
                return {"hit": True, "reason": f"len-diff:{len(r.content) - self.baseline['len']}",
                        "payload": variant, "variants_tried": variants_tried,
                        "code": r.status_code, "response": r}

        return {"hit": False, "reason": "no-hit", "payload": payload,
                "variants_tried": variants_tried}

    # ---------- verify ----------

    def verify(self, url_fn, payload, method="GET", data_fn=None,
               detect_markers=None, times=2):
        """
        Second independent check: try payload `times` more with slightly different
        mutation/time. If it hits again — confirmed.
        Returns True if confirmed.
        """
        confirmed = 0
        for i in range(times):
            time.sleep(0.15)
            # use a mutated variant (but NOT base) to reduce server-side caching effect
            variants = mutate(payload, n=2, base_first=False)
            variant = variants[0] if variants else payload

            if method == "GET":
                r = self.http.get(url_fn(variant))
            else:
                r = self.http.post(url_fn(variant), data=data_fn(variant) if data_fn else None)
            if not r or r.status_code in (403, 406, 429, 503):
                continue

            # same checks as inject
            if variant in r.text and "<script" in variant.lower():
                if "&lt;" not in r.text[:200]:
                    confirmed += 1
                    continue
            if detect_markers:
                low = r.text.lower()
                if any(m.lower() in low for m in detect_markers):
                    confirmed += 1
                    continue
            if self.baseline and abs(len(r.content) - self.baseline["len"]) > 200:
                confirmed += 1
                continue

        if confirmed >= max(1, times - 1):
            self.stats["verified"] += 1
            return True
        return False

    # ---------- auto-dump ----------

    def auto_dump(self, finding, target_url, param_name):
        """
        When sqli/lfi/etc detected — call the appropriate dump module.
        Returns dump result or None.
        """
        kind = finding.get("kind", "") or finding.get("type", "")
        if "sqli" in kind.lower():
            mod_name = "sqli_dump"
            cat = "dump"
        elif "lfi" in kind.lower():
            mod_name = "lfi_dump"
            cat = "dump"
        elif "ssrf" in kind.lower():
            mod_name = "ssrf_dump"
            cat = "dump"
        elif "xxe" in kind.lower():
            mod_name = "xxe_dump"
            cat = "dump"
        else:
            return None

        try:
            from core.loader import ModuleLoader
            loader = ModuleLoader()
            m = loader.load(cat, mod_name)
            if not m:
                return None
            print(f"    [auto-dump] triggering {cat}/{mod_name}", flush=True)
            self.stats["dumps"] += 1
            return m.run(self.session, self.logger)
        except Exception as e:
            if self.logger:
                self.logger.warn("auto_dump_fail", module=mod_name, error=str(e))
            return None

    # ---------- severity upgrade ----------

    def escalate_severity(self, base_severity, finding, response_text=""):
        """
        Auto-escalate if context warrants:
          - reflected XSS + session cookie in text -> critical (cookie theft)
          - SQLi + admin panel in text -> critical
          - error message contains password/hash -> critical
          - response size > 100kb with interesting keyword -> high
        """
        base = base_severity
        rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        target = rank.get(base, 0)

        low = (response_text or "").lower()
        if any(k in low for k in ("jsessionid", "sessionid", "phpsessid", "asp.net_sessionid")):
            target = max(target, 4)  # session visible -> critical
        if any(k in low for k in ("admin", "administrator", "root:")):
            target = max(target, 3)
        if any(k in low for k in ("password", "passwd", "secret", "api_key", "private key")):
            target = max(target, 4)

        for name, r in rank.items():
            if r == target:
                return name
        return base

    # ---------- summary ----------

    def summary(self):
        return dict(self.stats)


# ============ helper: full-cycle probe for a module ============

def run_full_probe(probe, url_fn, payloads, param_name,
                   method="GET", data_fn=None, detect_markers=None,
                   severity_base="medium", kind="unknown", target_url=None):
    """
    Full cycle: inject every payload → verify hits → auto-dump sqli/lfi → escalate severity.
    Returns list of verified findings.
    """
    findings = []
    for i, p in enumerate(payloads, 1):
        r = probe.inject(url_fn, p, method=method, data_fn=data_fn,
                         detect_markers=detect_markers)
        if not r.get("hit"):
            continue

        # verify
        confirmed = probe.verify(url_fn, p, method=method, data_fn=data_fn,
                                 detect_markers=detect_markers, times=2)
        if not confirmed:
            print(f"    · unverified (skipped): {p[:50]}", flush=True)
            continue

        # severity
        resp_text = ""
        if "response" in r and r["response"] is not None:
            resp_text = r["response"].text
        sev = probe.escalate_severity(severity_base, r, resp_text)

        finding = {
            "param": param_name,
            "payload": r["payload"],
            "reason": r["reason"],
            "severity": sev,
            "verified": True,
        }
        findings.append(finding)

        # auto-dump on injection
        if any(k in kind.lower() for k in ("sqli", "lfi", "ssrf", "xxe")):
            dump_result = probe.auto_dump({"kind": kind}, target_url or "", param_name)
            if dump_result:
                finding["dump"] = True

    return findings
