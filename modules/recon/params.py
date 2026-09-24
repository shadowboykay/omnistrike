"""params — hidden parameter discovery via arjun-style wordlist probing"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.http import HttpClient

PARAMS = ["id","page","file","path","url","redirect","next","return","callback","ref",
          "debug","test","admin","user","username","email","token","key","api_key","secret",
          "q","s","search","query","lang","view","action","cmd","exec","load","include",
          "template","tpl","cat","category","product","item","order","uid","gid","pid"]

class Params:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        base = http.get(target)
        if not base: return {"params": []}
        base_len = len(base.content)
        found = []
        def probe(p):
            r = http.get(target, params={p: "omni_probe_1"})
            if not r: return None
            # length deviation = parameter accepted / reflected
            if abs(len(r.content) - base_len) > 20 or "omni_probe_1" in r.text:
                return p
            return None
        with ThreadPoolExecutor(max_workers=session.threads) as ex:
            futs = [ex.submit(probe, p) for p in PARAMS]
            for f in as_completed(futs):
                p = f.result()
                if p:
                    found.append(p)
                    print(f"  [+] param: {p}")
                    logger.finding("param", "low", f"accepted: {p}")
        return {"target": target, "params": found}
