"""browser_behavior — human-like request pattern (referer chain, pauses, click-order)"""
import random, time
from core.http import HttpClient


class BrowserBehavior:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        base_url = session.target.rstrip("/")
        host = base_url.split("//")[-1].split("/")[0]

        # realistic browse pattern
        pages = [
            ("/", None),
            ("/", "/"),                      # reload
            ("/about", "/"),
            ("/contact", "/about"),
            ("/login", "/"),
            ("/", "/login"),                 # back
        ]

        results = []
        for i, (path, referer) in enumerate(pages):
            headers = {}
            if referer:
                headers["Referer"] = base_url + referer

            t0 = time.time()
            r = http.get(base_url + path, headers=headers)
            dt = time.time() - t0

            if r:
                print(f"  {i+1}/{len(pages)} {path:15s} ref={referer or '-':12s} {r.status_code} {dt:.2f}s")
                results.append({"path": path, "referer": referer,
                                "code": r.status_code, "time": dt})

            # human-like pause 0.5-3s
            pause = random.uniform(0.5, 3.0)
            time.sleep(pause)

        avg_time = sum(r["time"] for r in results) / len(results) if results else 0
        print(f"[browser_behavior] {len(results)} pages, avg time {avg_time:.2f}s")
        return {"results": results, "avg_time": avg_time}
