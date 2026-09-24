"""hpp — HTTP Parameter Pollution probe"""
from core.http import HttpClient

class Hpp:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        from urllib.parse import urlparse, parse_qs
        u = urlparse(target)
        params = parse_qs(u.query)
        if not params:
            print("[hpp] no params in URL"); return {"findings": []}

        findings = []
        for name, vals in params.items():
            original = vals[0]
            tests = [
                f"{name}={original}&{name}=omni_injected",
                f"{name}=omni_injected&{name}={original}",
                f"{name}={original}%26{name}=omni_injected",
                f"{name}={original}%3b{name}=omni_injected",
            ]
            for test in tests:
                new_url = target.split("?")[0] + "?" + test
                r = http.get(new_url)
                if not r: continue
                if "omni_injected" in r.text and original not in r.text:
                    findings.append({"param":name,"test":test,"type":"override"})
                    print(f"  [!] HPP: {name} override")
                    logger.finding("hpp","medium",f"{name} -> {test}")
                elif "omni_injected" in r.text and original in r.text:
                    findings.append({"param":name,"test":test,"type":"both"})
                    logger.finding("hpp","low",f"{name} both reflected")

        print(f"[hpp] {len(findings)}")
        return {"findings": findings}
