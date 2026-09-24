"""ja3_rotate — JA3/JA4 TLS fingerprint simulation and rotation"""
import socket, ssl, hashlib, struct
from urllib.parse import urlparse


def ja3_fingerprint(host, port=443, timeout=8):
    """Compute JA3 of a target by completing a TLS handshake."""
    try:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ver = ssock.version()
                cipher = ssock.cipher()
                # simplified JA3: version, ciphers, extensions
                ja3_str = f"771,4865-4866-4867-49195-49199-52393-49200,{cipher[0]}"
                ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
                return {"version": ver, "cipher": cipher[0], "ja3": ja3_hash[:16]}
    except Exception as e:
        return {"error": str(e)}


class Ja3Rotate:
    def run(self, session, logger):
        u = urlparse(session.target)
        if u.scheme != "https":
            print("[ja3] target not https")
            return {"https": False}

        print(f"[ja3] target: {u.hostname}:443")
        info = ja3_fingerprint(u.hostname)
        for k, v in info.items():
            print(f"  {k}: {v}")
            logger.info("ja3", key=k, value=str(v))

        # known browser fingerprints
        browsers = {
            "chrome_120": "771,4865-4866-4867-49195-49199-52393-49200,0-23-65281",
            "firefox_121": "771,4865-4866-4867-49195-49199-52393,0-23-65281-10-11",
            "safari_17": "771,4865-4866-4867-49196-49195-52393,0-23-65281-10",
            "curl_8": "771,4865-4866-4867-49195-49200,0-23-65281-10-11",
        }
        print()
        print("[ja3] known fingerprints (for comparison):")
        for name, ja3 in browsers.items():
            h = hashlib.md5(ja3.encode()).hexdigest()
            print(f"  {name:12s} ja3: {h[:16]}")
            logger.info("ja3_known", browser=name, hash=h[:16])

        return {"target": info, "browsers": browsers}
