"""h2c_smuggling — HTTP/2 cleartext smuggling probe"""
from core.http import HttpClient

class H2cSmuggling:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        # basic probe: send Upgrade: h2c header
        r = http.get(target, headers={
            "Connection": "Upgrade, HTTP2-Settings",
            "Upgrade": "h2c",
            "HTTP2-Settings": "AAMAAABkAAQAAP__",
        })
        if not r: return {}

        upgraded = r.headers.get("Upgrade","").lower() == "h2c" or r.status_code == 101
        print(f"[h2c] status={r.status_code} upgrade={upgraded}")

        if upgraded:
            logger.finding("h2c_upgrade","high","server accepts h2c upgrade")
            # try path override via internal admin
            for admin in ["/admin","/internal","/metrics","/health"]:
                r2 = http.get(target + admin, headers={
                    "Connection": "Upgrade, HTTP2-Settings",
                    "Upgrade": "h2c",
                    "HTTP2-Settings": "AAMAAABkAAQAAP__",
                })
                if r2 and r2.status_code == 200:
                    logger.finding("h2c_internal","critical",f"h2c exposes {admin}")
                    print(f"  [!] h2c internal: {admin}")
        return {"upgraded": upgraded}
