"""payload_obfuscate — obfuscate payload for WAF bypass (URL/HTML/JS/hex/case)"""
import urllib.parse, random, base64

def url_enc(s): return urllib.parse.quote(s, safe="")
def double_url_enc(s): return urllib.parse.quote(url_enc(s), safe="")
def html_ent(s):
    return "".join(f"&#x{ord(c):x};" if random.random() < 0.7 else c for c in s)
def js_esc(s): return "".join(f"\\x{ord(c):02x}" for c in s)
def hex_esc(s): return "".join(f"%{ord(c):02x}" for c in s)
def case_random(s): return "".join(c.upper() if random.random()<0.5 else c.lower() for c in s)
def base64_js(s): return f"eval(atob('{base64.b64encode(s.encode()).decode()}'))"
def comment_inject(s): return s.replace(" ", "/**/").replace("<", "<!---->")

METHODS = {
    "url": url_enc, "double_url": double_url_enc, "html": html_ent,
    "js": js_esc, "hex": hex_esc, "case": case_random, "base64": base64_js,
    "comment": comment_inject,
}

class PayloadObfuscate:
    def run(self, session, logger):
        payload = session.target
        print(f"[payload_obfuscate] input: {payload[:80]}")
        results = {}
        for name, fn in METHODS.items():
            try:
                out = fn(payload)
                results[name] = out
                print(f"  {name:12s} -> {out[:80]}")
            except Exception as e:
                print(f"  {name:12s} error: {e}")
        return {"results": results}
