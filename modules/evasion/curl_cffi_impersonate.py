"""curl_cffi_impersonate — real browser TLS+HTTP2 fingerprint via curl_cffi"""
from core.http import HttpClient


class CurlCffiImpersonate:
    def run(self, session, logger):
        try:
            from curl_cffi import requests as curl_requests
        except ImportError:
            print("[impersonate] install: pip install curl_cffi")
            return {"installed": False}

        browsers = ["chrome120", "chrome119", "firefox120", "safari17_0",
                    "edge101", "chrome_android", "safari_ios"]

        target = session.target
        results = []
        for b in browsers:
            try:
                r = curl_requests.get(target, impersonate=b, verify=False, timeout=15)
                code = r.status_code
                size = len(r.content)
                print(f"  ✓ {b:20s} {code} {size}b")
                results.append({"browser": b, "code": code, "size": size})
                logger.info("impersonate", browser=b, code=code, size=size)
            except Exception as e:
                print(f"  ✗ {b:20s} {type(e).__name__}: {str(e)[:40]}")

        print(f"[curl_cffi_impersonate] {len(results)}/{len(browsers)} succeeded")
        return {"results": results}
