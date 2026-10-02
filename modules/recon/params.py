"""params v2 — hidden parameter discovery with baseline+verify (kills false positives)"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.http import HttpClient
from core.verify import baseline, verify, confidence, is_signal, random_token

PARAMS = ["id","page","file","path","url","redirect","next","return","callback","ref",
          "debug","test","admin","user","username","email","token","key","api_key","secret",
          "q","s","search","query","lang","view","action","cmd","exec","load","include",
          "template","tpl","cat","category","product","item","order","uid","gid","pid"]

PROBE_VALUE = "omni_probe_" + random_token(8)
NOISE_PARAMS = {"q", "s", "search", "query", "callback"}


class Params:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        noise_param = "omni_noise_" + random_token(10)

        def noise_req():
            try:
                return http.get(target, params={noise_param: "x"})
            except Exception:
                return None

        bl = baseline(noise_req, n=3, delay=0.15)
        if not bl:
            print("[params] no baseline — target unreachable")
            return {"params": []}

        noise_delta = max(bl.get("len_spread", 0), 30)
        print(f"[params] baseline len={bl['len']} noise_delta={noise_delta}")

        found = []

        def probe(p):
            try:
                r = http.get(target, params={p: PROBE_VALUE})
            except Exception:
                return None
            if not r:
                return None
            body = r.text or ""
            delta = abs(len(body) - bl["len"])
            reflected = PROBE_VALUE in body

            if delta <= noise_delta:
                return None
            if not reflected and delta <= noise_delta * 2:
                return None

            def rep():
                try:
                    return http.get(target, params={p: PROBE_VALUE})
                except Exception:
                    return None

            def predicate(s):
                d2 = abs(s["len"] - bl["len"])
                refl2 = PROBE_VALUE in s["body"]
                return d2 > noise_delta or refl2

            ratio, hits = verify(rep, predicate, n=2, delay=0.2)

            signal_strength = 0.4
            if reflected and delta > noise_delta * 3:
                signal_strength = 0.6
            if reflected and len(body) > len(bl["body"]) * 1.5:
                signal_strength = 0.7

            conf = confidence(
                signal_strength=signal_strength,
                verify_ratio=ratio,
                baseline=bl,
                sample={"status": r.status_code, "len": len(body)},
                floor=0.55,
            )
            if not is_signal(conf, floor=0.55):
                return None

            return {"param": p, "delta": delta, "reflected": reflected,
                    "verify_hits": hits, "confidence": conf}

        max_workers = min(5, max(1, getattr(session, "threads", 5)))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = [ex.submit(probe, p) for p in PARAMS]
            for f in as_completed(futs):
                res = f.result()
                if not res:
                    continue
                found.append(res["param"])
                print(f"  [+] param: {res['param']} (delta={res['delta']} conf={res['confidence']})")
                logger.finding("param", "low",
                               f"{res['param']} accepted (delta={res['delta']}, conf={res['confidence']})")

        print(f"[params] {len(found)} params confirmed (baseline-noise={noise_delta}b)")
        return {"target": target, "params": found, "baseline_len": bl["len"],
                "noise_delta": noise_delta}
