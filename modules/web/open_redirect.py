"""open_redirect — open redirect probe across common param names"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient

EVIL = "https://omni-redirect-canary.example"
PARAMS = ["next","url","redirect","redirect_uri","return","return_to","return_url",
          "continue","dest","destination","r","u","goto","target","link","out"]

class OpenRedirect:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        findings = []
        u = urlparse(target)
        base_q = parse_qs(u.query)
        for name in PARAMS:
            q = dict(base_q); q[name] = [EVIL]
            new_url = urlunparse(u._replace(query=urlencode(q, doseq=True)))
            r = http.get(new_url, allow_redirects=False)
            if not r: continue
            loc = r.headers.get("Location","")
            if EVIL in loc or loc.startswith(EVIL):
                findings.append({"param":name,"location":loc})
                print(f"  [!] open redirect: {name} -> {loc[:80]}")
                logger.finding("open_redirect", "medium", f"{name} -> {loc[:80]}")
        print(f"[open_redirect] done: {len(findings)}")
        return {"findings": findings}
