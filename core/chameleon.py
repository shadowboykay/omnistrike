# core/chameleon.py — adaptive attack mode: detect target type, change behavior
import time, re
from core.http import HttpClient


# Signatures for detection
WAF_SIGS = {
    "cloudflare":  ["cloudflare", "cf-ray", "cf-cache-status", "__cfduid"],
    "akamai":      ["akamai", "ak-bmsc", "x-akamai"],
    "imperva":     ["imperva", "incap_ses", "visid_incap", "x-iinfo"],
    "aws_waf":     ["awselb", "x-amzn-requestid", "aws-waf"],
    "sucuri":      ["sucuri", "x-sucuri-id"],
    "f5_bigip":    ["bigip", "f5", "ts01", "x-wa-info"],
    "fastly":      ["fastly", "x-served-by", "x-fastly"],
}

HONEYPOT_SIGS = {
    "default_credentials_page":  ["admin/admin", "root/root"],
    "too_many_services":         ["22", "23", "80", "443", "3389", "5900"],
    "emulated_ssh":              ["SSH-2.0-OpenSSH_6.6.1p1"],
    "kfsensor":                  ["Server: Apache/2.2.8"],
    "fake_wordpress":            ["wp-admin", "wp-content", "__nouse"],
    "too_fast_response":         None,  # detected by time
}

EDR_SIGS = {
    "crowdstrike": ["cs-header", "x-crowdstrike"],
    "sentinelone": ["x-sentinelone"],
    "defender":    ["x-msedge-ref"],
}

IDS_SIGS = {
    "suricata": ["x-suricata"],
    "snort":    ["x-snort"],
}


class Chameleon:
    """
    Adaptive attack mode.
    Detects what's on the other side and picks behavior:
      - honeypot  → stop, mark target as trap
      - waf       → slow + mutations + jitter
      - ids       → very slow + long jitter
      - edr       → evasion techniques
      - normal    → full speed
    """

    STRATEGIES = {
        "honeypot": {
            "attack": False,
            "delay_range": (5, 15),
            "message": "⚠ Honeypot detected — ABORTING to avoid tarpit",
        },
        "waf_cloudflare": {
            "attack": True,
            "delay_range": (3, 8),
            "use_mutations": True,
            "jitter": True,
            "message": "Cloudflare WAF — slow + mutations",
        },
        "waf_akamai": {
            "attack": True,
            "delay_range": (3, 10),
            "use_mutations": True,
            "jitter": True,
            "message": "Akamai WAF — slow + mutations",
        },
        "waf_imperva": {
            "attack": True,
            "delay_range": (4, 12),
            "use_mutations": True,
            "jitter": True,
            "message": "Imperva WAF — slow + mutations",
        },
        "waf_aws": {
            "attack": True,
            "delay_range": (2, 6),
            "use_mutations": True,
            "message": "AWS WAF — medium speed",
        },
        "ids": {
            "attack": True,
            "delay_range": (8, 20),
            "jitter": True,
            "low_and_slow": True,
            "message": "IDS detected — low and slow",
        },
        "edr": {
            "attack": True,
            "delay_range": (1, 3),
            "use_evasion": True,
            "message": "EDR on host — evasion mode",
        },
        "normal": {
            "attack": True,
            "delay_range": (0.3, 1.0),
            "message": "Normal target — full speed",
        },
    }

    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        self.http = HttpClient(session, logger)
        self.detected = {}
        self.strategy = None

    def detect(self):
        """Probe target, identify what's on the other side."""
        print(f"[chameleon] probing {self.session.target}")
        t0 = time.time()
        r = self.http.get(self.session.target)
        dt = time.time() - t0

        if not r:
            print("  ✗ no response")
            self.detected = {"type": "unreachable"}
            self.strategy = self.STRATEGIES["normal"]
            return self.detected

        headers_str = str(r.headers).lower()
        body_lower = r.text.lower()
        blob = headers_str + " " + body_lower

        print(f"  response: {r.status_code} {len(r.content)}b in {dt:.2f}s")

        # 1. honeypot check
        honeypot_hits = []
        for name, sigs in HONEYPOT_SIGS.items():
            if sigs is None:
                continue
            hits = [s for s in sigs if s.lower() in blob]
            if len(hits) >= 2:
                honeypot_hits.append(name)

        # additional honeypot markers
        if any(m in blob for m in ["kfsensor", "dionaea", "cowrie", "glastopf"]):
            honeypot_hits.append("known_honeypot")

        # fast response = possible emulator
        if dt < 0.05 and len(r.content) < 500:
            honeypot_hits.append("too_fast_emulator")

        if honeypot_hits:
            self.detected = {"type": "honeypot", "markers": honeypot_hits}
            self.strategy = self.STRATEGIES["honeypot"]
            print(f"  ⚠ HONEYPOT: {honeypot_hits}")
            self.logger.finding("chameleon_honeypot", "critical",
                                f"Target looks like honeypot: {honeypot_hits}")
            return self.detected

        # 2. WAF check
        for waf_name, sigs in WAF_SIGS.items():
            hits = [s for s in sigs if s in blob]
            if hits:
                strat_key = f"waf_{waf_name.replace('_waf','').replace('_bigip','').replace('_','_')}"
                if strat_key not in self.STRATEGIES:
                    strat_key = "waf_cloudflare"  # default WAF strategy
                self.detected = {"type": "waf", "name": waf_name, "markers": hits}
                self.strategy = self.STRATEGIES.get(strat_key, self.STRATEGIES["waf_cloudflare"])
                print(f"  ✓ WAF: {waf_name}")
                self.logger.finding("chameleon_waf", "info", f"WAF: {waf_name}")
                return self.detected

        # 3. IDS check
        for ids_name, sigs in IDS_SIGS.items():
            hits = [s for s in sigs if s in blob]
            if hits:
                self.detected = {"type": "ids", "name": ids_name, "markers": hits}
                self.strategy = self.STRATEGIES["ids"]
                print(f"  ✓ IDS: {ids_name}")
                return self.detected

        # 4. EDR check
        for edr_name, sigs in EDR_SIGS.items():
            hits = [s for s in sigs if s in blob]
            if hits:
                self.detected = {"type": "edr", "name": edr_name, "markers": hits}
                self.strategy = self.STRATEGIES["edr"]
                print(f"  ✓ EDR: {edr_name}")
                return self.detected

        # 5. normal
        self.detected = {"type": "normal"}
        self.strategy = self.STRATEGIES["normal"]
        print("  · normal target")
        return self.detected

    def apply_delay(self):
        """Sleep according to strategy."""
        import random
        if not self.strategy:
            return
        lo, hi = self.strategy.get("delay_range", (0, 0))
        if hi > 0:
            time.sleep(random.uniform(lo, hi))

    def should_attack(self):
        return self.strategy.get("attack", True) if self.strategy else True

    def summary(self):
        return {
            "detected": self.detected,
            "strategy": {k: v for k, v in (self.strategy or {}).items() if k != "message"},
            "message": (self.strategy or {}).get("message", ""),
        }
