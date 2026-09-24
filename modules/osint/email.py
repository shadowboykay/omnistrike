"""email — email OSINT: format guess, MX check, leak hints"""
import re
from core.http import HttpClient

FIRST = ["john","jane","alex","max","maria","anna","david","sarah","michael","elena",
         "pavel","olga","sergey","irina","andrey","natalia","vladimir","tatiana"]
LAST  = ["smith","ivanov","petrov","sidorov","kuznetsov","popov","sokolov","volkov",
         "morozov","novikov","fedorov","mikhailov"]

class Email:
    def run(self, session, logger):
        target = session.target
        # if target is a domain — guess formats
        if "." in target and "@" not in target:
            domain = target.replace("https://","").replace("http://","").split("/")[0]
            print(f"[email] domain: {domain}")
            http = HttpClient(session, logger)
            r = http.get(f"https://dns.google/resolve?name={domain}&type=MX",
                         headers={"Accept":"application/dns-json"})
            if r:
                mx = [a.get("data") for a in r.json().get("Answer",[])]
                print(f"  MX: {mx}")
                logger.finding("email_mx","info",f"{domain} -> {mx}")
            patterns = []
            for f in FIRST[:5]:
                for l in LAST[:5]:
                    patterns.append(f"{f}.{l}@{domain}")
                    patterns.append(f"{f}{l}@{domain}")
                    patterns.append(f"{f[0]}{l}@{domain}")
            print(f"  generated {len(patterns)} candidate emails")
            return {"domain": domain, "mx": mx if r else [], "candidates": patterns}

        # if target is email
        email = target
        user, domain = email.split("@")
        print(f"[email] checking {email}")
        # gravatar hash
        import hashlib
        h = hashlib.md5(email.lower().encode()).hexdigest()
        url = f"https://www.gravatar.com/avatar/{h}?d=404"
        http = HttpClient(session, logger)
        r = http.get(url)
        if r and r.status_code == 200:
            print(f"  [!] gravatar exists")
            logger.finding("gravatar","info",email)
        return {"email": email, "gravatar_hash": h, "gravatar": r.status_code == 200 if r else False}
