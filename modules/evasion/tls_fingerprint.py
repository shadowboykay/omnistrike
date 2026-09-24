"""tls_fingerprint — check TLS fingerprint (JA3) + mimic browser via curl_cffi if available"""
from core.http import HttpClient
import hashlib

class TlsFingerprint:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        # check if curl_cffi available for impersonation
        try:
            from curl_cffi import requests as curl_requests
            print("[tls_fingerprint] curl_cffi available — using browser impersonation")
            r = curl_requests.get(session.target, impersonate="chrome120", verify=False, timeout=15)
            print(f"  status={r.status_code}")
            print(f"  headers: {dict(r.headers)}")
            logger.finding("tls_impersonate","info","chrome120 impersonation succeeded")
            return {"impersonation":"chrome120","code":r.status_code}
        except ImportError:
            print("[tls_fingerprint] curl_cffi not installed")
            print("  install: pip install curl_cffi")
            # fall back to TLS info
            import ssl, socket
            from urllib.parse import urlparse
            u = urlparse(session.target)
            if u.scheme != "https":
                print("  target not https, skipping")
                return {}
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((u.hostname, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=u.hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        ver = ssock.version()
                        print(f"  TLS: {ver}, cipher: {cipher[0]}")
                        logger.finding("tls_info","info",f"{ver} {cipher[0]}")
            except Exception as e:
                print(f"  tls error: {e}")
            return {}
