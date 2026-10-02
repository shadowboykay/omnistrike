"""password_reset_flaws v2 — password reset flow analysis with verify.

Классы уязвимостей:
  1. Token in reset-link (утечка) — critical
  2. Short token (< 16 chars) — high
  3. Token reuse — 2 reset запроса дают одинаковый токен
  4. Sequential tokens — 2 email дают похожие токены
  5. Host header poisoning в ссылке сброса — critical
  6. User enumeration через timing — medium
  7. No rate-limit — info
  8. Same response for existent/nonexistent email — info (не finding)
"""
import re
import time
import secrets
import statistics
from urllib.parse import urlparse
from core.http import HttpClient
from core.verify import verify, confidence, is_signal


RESET_PATHS = [
    "/forgot", "/forgot-password", "/password/forgot", "/password/reset",
    "/reset", "/reset-password", "/account/recover", "/account/forgot",
    "/users/password/new", "/auth/forgot", "/api/password/reset",
    "/api/auth/forgot", "/api/v1/password/forgot", "/password-recovery",
]

# regex для токена в Location или body
TOKEN_RE_LOC = re.compile(r"[?&](token|reset_token|code|key|t)=([A-Za-z0-9_\-\.]{8,})")
TOKEN_RE_BODY = re.compile(r"(?:token|code|reset|key)[\"'\s:=]+([A-Za-z0-9_\-\.]{4,80})[\"'<]", re.I)


def _entropy(s):
    """Приблизительная энтропия строки (bits)."""
    if not s:
        return 0
    import math
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    ent = 0
    n = len(s)
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent * n


def _is_sequential(t1, t2):
    """Проверяет, что два токена отличаются на 1 (инкрементальные)."""
    if not t1 or not t2 or len(t1) != len(t2):
        return False
    # только если токены чисто цифровые или hex
    try:
        i1 = int(t1, 16) if all(c in "0123456789abcdefABCDEF" for c in t1) else int(t1)
        i2 = int(t2, 16) if all(c in "0123456789abcdefABCDEF" for c in t2) else int(t2)
        return abs(i1 - i2) < 10
    except Exception:
        return False


class PasswordResetFlaws:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)

        print(f"[reset v2] target: {base}")
        print(f"[reset v2] testing {len(RESET_PATHS)} reset endpoints")

        # === Phase 1: найти работающий endpoint ===
        live_endpoints = []
        for path in RESET_PATHS:
            try:
                r = http.get(base + path, allow_redirects=False)
            except Exception:
                continue
            if not r:
                continue
            if r.status_code in (200, 405):
                # проверяем что принимает POST
                try:
                    r2 = http.post(base + path, data={"email": "probe@example.com"},
                                   allow_redirects=False)
                except Exception:
                    continue
                if r2 and r2.status_code in (200, 201, 202, 204, 301, 302, 303, 307, 308):
                    live_endpoints.append(path)
                    print(f"[reset v2] live endpoint: {path} (GET={r.status_code}, POST={r2.status_code})")

        if not live_endpoints:
            print(f"[reset v2] no working reset endpoint found — skip")
            return {"findings": [], "live_endpoints": []}

        findings = []

        # === Phase 2: анализ каждого endpoint ===
        for path in live_endpoints:
            url = base + path
            print()
            print(f"[reset v2] analyzing {path}")

            # baseline: 2 запроса с уникальным email
            email_1 = f"omni-a-{secrets.token_hex(4)}@example.com"
            email_2 = f"omni-b-{secrets.token_hex(4)}@example.com"

            try:
                r1 = http.post(url, data={"email": email_1}, allow_redirects=False)
            except Exception:
                continue
            if not r1:
                continue

            # --- Token leak ---
            body = r1.text or ""
            loc = r1.headers.get("Location", "")

            token = None
            source = None

            m = TOKEN_RE_LOC.search(loc)
            if m:
                token = m.group(2)
                source = "Location"
            else:
                m = TOKEN_RE_BODY.search(body)
                if m:
                    token = m.group(1)
                    source = "body"

            if token:
                ent = _entropy(token)
                token_len = len(token)

                # short token
                if token_len < 16:
                    conf = confidence(0.75, 1.0)
                    if is_signal(conf, floor=0.55, module="password_reset"):
                        findings.append({
                            "type": "short_reset_token",
                            "severity": "high",
                            "path": path,
                            "token_len": token_len,
                            "source": source,
                            "entropy_bits": round(ent, 1),
                            "confidence": conf,
                        })
                        print(f"  SHORT token ({token_len} chars, {ent:.1f} bits) in {source}")
                        logger.finding("reset_short_token", "high",
                                       f"{path} len={token_len} bits={ent:.1f}")

                # low entropy
                elif ent < 60:
                    conf = confidence(0.7, 1.0)
                    if is_signal(conf, floor=0.55, module="password_reset"):
                        findings.append({
                            "type": "low_entropy_token",
                            "severity": "medium",
                            "path": path,
                            "token_len": token_len,
                            "entropy_bits": round(ent, 1),
                            "confidence": conf,
                        })
                        print(f"  LOW ENTROPY token ({ent:.1f} bits)")
                        logger.finding("reset_low_entropy", "medium", path)

                # --- Token reuse ---
                time.sleep(0.3)
                try:
                    r2 = http.post(url, data={"email": email_1}, allow_redirects=False)
                except Exception:
                    r2 = None

                if r2:
                    loc2 = r2.headers.get("Location", "")
                    body2 = r2.text or ""
                    token2 = None
                    m2 = TOKEN_RE_LOC.search(loc2) or TOKEN_RE_BODY.search(body2)
                    if m2:
                        token2 = m2.group(2) if m2.re is TOKEN_RE_LOC else m2.group(1)

                    if token2 and token == token2:
                        conf = confidence(0.95, 1.0)
                        if is_signal(conf, floor=0.55, module="password_reset"):
                            findings.append({
                                "type": "token_reuse",
                                "severity": "critical",
                                "path": path,
                                "token": token[:30],
                                "confidence": conf,
                            })
                            print(f"  TOKEN REUSE — same token twice")
                            logger.finding("reset_token_reuse", "critical", path)

                    # --- Sequential tokens ---
                    if token2 and _is_sequential(token, token2):
                        conf = confidence(0.9, 1.0)
                        if is_signal(conf, floor=0.55, module="password_reset"):
                            findings.append({
                                "type": "sequential_token",
                                "severity": "critical",
                                "path": path,
                                "token_a": token,
                                "token_b": token2,
                                "confidence": conf,
                            })
                            print(f"  SEQUENTIAL tokens: {token} -> {token2}")
                            logger.finding("reset_sequential", "critical", path)

            # --- Host header poisoning ---
            canary = f"canary-{secrets.token_hex(4)}.example"
            for h in ("Host", "X-Forwarded-Host", "X-Original-Host"):
                try:
                    rh = http.post(url, data={"email": email_1},
                                   headers={h: canary}, allow_redirects=False)
                except Exception:
                    continue
                if not rh:
                    continue
                if canary in (rh.text or "") or canary in rh.headers.get("Location", ""):
                    findings.append({
                        "type": "reset_host_poison",
                        "severity": "critical",
                        "path": path,
                        "header": h,
                        "confidence": 0.9,
                    })
                    print(f"  HOST POISON via {h}")
                    logger.finding("reset_host_poison", "critical", f"{path} {h}")
                    break

            # --- Timing enumeration ---
            timings_exist = []
            timings_missing = []
            for _ in range(3):
                try:
                    t0 = time.time()
                    http.post(url, data={"email": "admin@example.com"}, allow_redirects=False)
                    timings_exist.append(time.time() - t0)
                    t0 = time.time()
                    http.post(url, data={"email": f"nobody-{secrets.token_hex(4)}@nowhere.example"},
                              allow_redirects=False)
                    timings_missing.append(time.time() - t0)
                except Exception:
                    continue
                time.sleep(0.2)

            if timings_exist and timings_missing:
                t_exist = statistics.median(timings_exist)
                t_missing = statistics.median(timings_missing)
                diff_ms = abs(t_exist - t_missing) * 1000
                if diff_ms > 150:
                    findings.append({
                        "type": "reset_timing_enum",
                        "severity": "medium",
                        "path": path,
                        "diff_ms": round(diff_ms),
                        "exist_ms": round(t_exist * 1000),
                        "missing_ms": round(t_missing * 1000),
                    })
                    print(f"  TIMING ENUM: {diff_ms:.0f}ms diff (exist={t_exist*1000:.0f}ms missing={t_missing*1000:.0f}ms)")
                    logger.finding("reset_timing", "medium", f"{path} diff={diff_ms:.0f}ms")

            # --- Rate-limit test (30 requests) ---
            rate_limited = False
            for i in range(30):
                try:
                    rr = http.post(url, data={"email": f"rl-{i}@example.com"},
                                   allow_redirects=False)
                except Exception:
                    continue
                if rr and rr.status_code == 429:
                    rate_limited = True
                    break
            if not rate_limited:
                findings.append({
                    "type": "no_rate_limit",
                    "severity": "info",
                    "path": path,
                    "requests_sent": 30,
                })
                print(f"  NO RATE-LIMIT after 30 requests")
                logger.finding("reset_no_ratelimit", "info", path)

        print()
        print(f"[reset v2] findings: {len(findings)}")
        return {
            "findings": findings,
            "live_endpoints": live_endpoints,
        }
