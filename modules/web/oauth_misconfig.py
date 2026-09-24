"""oauth_misconfig — OAuth 2.0 / OIDC misconfig probe"""
from urllib.parse import urlparse, urlencode, parse_qs
from core.http import HttpClient
from core.payload_source import get_payloads
from core.probe import Probe

class OauthMisconfig:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        probe = Probe(session, logger)
        probe.baseline_probe(target)

        u = urlparse(target)
        base = f"{u.scheme}://{u.netloc}"
        evil = "https://evil.attacker.example"
        findings = []

        # common OAuth endpoints
        oauth_paths = [
            "/oauth/authorize", "/oauth2/authorize", "/authorize", "/auth/oauth",
            "/oauth/authorize/", "/login/oauth/authorize", "/api/oauth/authorize",
            "/oauth2/auth", "/connect/authorize",
        ]

        for path in oauth_paths:
            # baseline check
            r = http.get(base + path, allow_redirects=False)
            if not r or r.status_code not in (200, 302, 400, 401): continue
            print(f"[oauth] found endpoint: {path}")
            logger.finding("oauth_endpoint", "info", path)

            # redirect_uri bypass
            redirect_params = ["redirect_uri", "redirect_url", "callback", "return_uri"]
            for rp in redirect_params:
                test_url = f"{base}{path}?{rp}={evil}&client_id=test&response_type=code"
                r2 = http.get(test_url, allow_redirects=False)
                if r2 and evil in r2.headers.get("Location", ""):
                    print(f"  [!] redirect_uri bypass: {rp}")
                    findings.append({"path": path, "param": rp,
                                     "type": "redirect_bypass", "severity": "critical"})
                    logger.finding("oauth_redirect", "critical", f"{path} {rp}")

                # path bypass variants
                for variant in [f"{evil}/callback", f"{evil}@legit.com", f"https://legit.com.{evil}",
                                f"{evil}%00.legit.com", f"//{evil[8:]}"]:
                    test_url = f"{base}{path}?{rp}={variant}&client_id=test"
                    r3 = http.get(test_url, allow_redirects=False)
                    if r3 and evil[8:] in r3.headers.get("Location", ""):
                        print(f"  [!] bypass variant: {variant[:40]}")
                        findings.append({"path": path, "param": rp, "variant": variant,
                                         "severity": "critical"})
                        logger.finding("oauth_redirect_bypass", "critical", variant[:60])

        # check for state parameter
        for path in oauth_paths[:3]:
            r = http.get(f"{base}{path}?client_id=test&response_type=code&redirect_uri={evil}")
            if r and r.status_code == 302:
                loc = r.headers.get("Location", "")
                if "state=" not in loc:
                    print(f"  [!] no state param: {path}")
                    findings.append({"path": path, "type": "no_state",
                                     "severity": "medium"})
                    logger.finding("oauth_no_state", "medium", path)

        print(f"[oauth] total: {len(findings)}")
        return {"findings": findings}
