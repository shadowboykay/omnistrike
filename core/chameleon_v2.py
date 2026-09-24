# core/chameleon_v2.py — behavioral analysis (headers + timing + response patterns)
import time
import re
import statistics
from core.http import HttpClient


class ChameleonV2:
    """
    Поведенческий анализ цели.

    Уровни детекта:
      1. Headers (как v1)
      2. Timing — слишком быстрый/медленный/постоянный
      3. Response stability — идентичные ответы = эмулятор
      4. Deep probe — паттерны honeypot (много сервисов одновременно)
      5. Fingerprint anomalies
    """

    WAF_HEADERS = {
        "cloudflare": ["cloudflare", "cf-ray", "cf-cache"],
        "akamai":     ["akamai", "x-akamai", "ak-bmsc"],
        "imperva":    ["imperva", "incap_ses", "x-iinfo"],
        "aws_waf":    ["awselb", "x-amzn-requestid"],
        "sucuri":     ["sucuri", "x-sucuri"],
        "f5":         ["bigip", "ts01", "x-wa-info"],
    }

    HONEYPOT_HEADERS = {
        "kfsensor":  ["kfsensor"],
        "cowrie":    ["cowrie", "ssh-2.0-openssh_6.0"],
        "dionaea":   ["dionaea"],
        "glastopf":  ["glastopf"],
        "tanner":    ["tanner"],
    }

    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        self.http = HttpClient(session, logger)
        self.signals = {}
        self.detected_type = None
        self.strategy = None

    # ---------- Level 1: Headers ----------
    def analyze_headers(self, r):
        headers = str(r.headers).lower()
        body = r.text.lower()[:3000]
        blob = headers + " " + body

        waf_found = []
        for waf, sigs in self.WAF_HEADERS.items():
            if any(s in blob for s in sigs):
                waf_found.append(waf)

        honeypot_found = []
        for hp, sigs in self.HONEYPOT_HEADERS.items():
            if any(s in blob for s in sigs):
                honeypot_found.append(hp)

        self.signals["waf_headers"] = waf_found
        self.signals["honeypot_headers"] = honeypot_found
        return {"waf": waf_found, "honeypot": honeypot_found}

    # ---------- Level 2: Timing ----------
    def analyze_timing(self, n=5):
        times = []
        for _ in range(n):
            t0 = time.time()
            r = self.http.get(self.session.target)
            dt = time.time() - t0
            times.append(dt)
            time.sleep(0.3)

        avg = statistics.mean(times)
        stdev = statistics.stdev(times) if len(times) > 1 else 0
        variance = max(times) - min(times)

        signals = []
        if avg < 0.05:
            signals.append("too_fast_emulator")
        elif avg > 5:
            signals.append("too_slow_tarpit")
        if stdev < 0.02:
            signals.append("suspiciously_stable")

        self.signals["timing"] = {
            "avg": round(avg, 3),
            "stdev": round(stdev, 3),
            "variance": round(variance, 3),
            "flags": signals,
        }
        return self.signals["timing"]

    # ---------- Level 3: Response stability ----------
    def analyze_stability(self, n=5):
        responses = []
        for _ in range(n):
            r = self.http.get(self.session.target)
            if r:
                responses.append((r.status_code, len(r.content), hash(r.text[:500])))
            time.sleep(0.2)

        unique_bodies = len(set(r[2] for r in responses))
        unique_sizes = len(set(r[1] for r in responses))

        signals = []
        if unique_bodies == 1 and unique_sizes == 1:
            signals.append("perfectly_identical_responses")

        self.signals["stability"] = {
            "unique_bodies": unique_bodies,
            "unique_sizes": unique_sizes,
            "total": len(responses),
            "flags": signals,
        }
        return self.signals["stability"]

    # ---------- Level 4: Deep probes ----------
    def analyze_deep_probes(self):
        probes = [
            ("/admin", "admin_panel"),
            ("/wp-admin", "wordpress"),
            ("/wp-login.php", "wordpress"),
            ("/phpmyadmin", "phpmyadmin"),
            ("/.git/config", "git_leak"),
            ("/.env", "env_leak"),
            ("/backup.zip", "backup_leak"),
            ("/server-status", "apache_status"),
        ]

        accessible = []
        for path, kind in probes:
            r = self.http.get(self.session.target.rstrip("/") + path)
            if r and r.status_code == 200:
                accessible.append({"path": path, "type": kind, "size": len(r.content)})

        # honeypot signal: too many critical paths accessible
        signals = []
        if len(accessible) >= 4:
            signals.append("too_many_accessible_paths")

        self.signals["deep_probes"] = {
            "accessible": accessible,
            "count": len(accessible),
            "flags": signals,
        }
        return self.signals["deep_probes"]

    # ---------- Verdict ----------
    def verdict(self):
        hp = self.signals.get("honeypot_headers", [])
        hp_strong = self.signals.get("deep_probes", {}).get("flags", [])
        hp_timing = self.signals.get("timing", {}).get("flags", [])
        hp_stable = self.signals.get("stability", {}).get("flags", [])

        honeypot_score = len(hp) * 3 + len(hp_strong) * 2 + len(hp_timing) + len(hp_stable)
        waf_score = len(self.signals.get("waf_headers", []))

        if honeypot_score >= 3:
            return "honeypot"
        if waf_score > 0:
            return "waf"
        return "normal"

    def strategy_for(self, kind):
        return {
            "honeypot": {
                "attack": False,
                "message": "⚠ HONEYPOT (behavioral) — ABORT",
                "delay_range": (10, 30),
            },
            "waf": {
                "attack": True,
                "message": "WAF — slow + mutations",
                "delay_range": (3, 8),
                "use_evasion": True,
            },
            "normal": {
                "attack": True,
                "message": "Normal — full speed",
                "delay_range": (0.3, 1.0),
            },
        }[kind]

    def run_analysis(self):
        print(f"[chameleon v2] target: {self.session.target}")
        print(f"[chameleon v2] behavioral analysis...")
        print()

        # baseline
        r = self.http.get(self.session.target)
        if not r:
            print("  ✗ no response")
            return None

        # Level 1
        print("=== Level 1: Headers ===")
        hdr = self.analyze_headers(r)
        print(f"  WAF: {hdr['waf'] or 'none'}")
        print(f"  Honeypot markers: {hdr['honeypot'] or 'none'}")

        # Level 2
        print("\n=== Level 2: Timing (5 probes) ===")
        t = self.analyze_timing(5)
        print(f"  avg: {t['avg']}s, stdev: {t['stdev']}, variance: {t['variance']}")
        print(f"  flags: {t['flags'] or 'none'}")

        # Level 3
        print("\n=== Level 3: Response Stability (5 probes) ===")
        s = self.analyze_stability(5)
        print(f"  unique bodies: {s['unique_bodies']}/{s['total']}")
        print(f"  unique sizes: {s['unique_sizes']}/{s['total']}")
        print(f"  flags: {s['flags'] or 'none'}")

        # Level 4
        print("\n=== Level 4: Deep Probes ===")
        d = self.analyze_deep_probes()
        print(f"  accessible critical paths: {d['count']}")
        for a in d["accessible"]:
            print(f"    + {a['path']} ({a['type']}, {a['size']}b)")
        print(f"  flags: {d['flags'] or 'none'}")

        # verdict
        kind = self.verdict()
        self.detected_type = kind
        self.strategy = self.strategy_for(kind)

        print()
        print("=" * 60)
        print(f"VERDICT: {kind.upper()}")
        print(f"STRATEGY: {self.strategy['message']}")
        print("=" * 60)

        if kind == "honeypot":
            self.logger.finding("chameleon_v2_honeypot", "critical",
                                f"behavioral honeypot: {self.signals}")
        elif kind == "waf":
            self.logger.finding("chameleon_v2_waf", "info",
                                f"WAF: {self.signals['waf_headers']}")
        else:
            self.logger.finding("chameleon_v2_normal", "info", "normal target")

        return {
            "verdict": kind,
            "strategy": self.strategy,
            "signals": self.signals,
        }


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from core.session import Session
    from core.logger import Logger
    target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    s = Session(target=target, timeout=10)
    l = Logger(s)
    c = ChameleonV2(s, l)
    c.run_analysis()
