"""xss_dom — DOM-based XSS detection via static JS analysis"""
import re
from core.http import HttpClient

SINKS = ["document.write","document.writeln","innerHTML","outerHTML","eval",
         "setTimeout","setInterval","Function(","script.src","location.href",
         "location.replace","location.assign","window.open","element.insertAdjacentHTML"]

SOURCES = ["location.hash","location.search","location.href","document.URL",
           "document.documentURI","document.referrer","window.name","document.cookie"]

class XssDom:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        target = session.target
        r = http.get(target)
        if not r: return {}

        # find JS files
        js_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)', r.text)
        js_urls.append("")  # inline

        findings = []
        for ju in js_urls[:10]:
            if ju:
                url = ju if ju.startswith("http") else target.rstrip("/") + "/" + ju.lstrip("/")
                jr = http.get(url)
                body = jr.text if jr else ""
            else:
                body = r.text

            for src in SOURCES:
                for sink in SINKS:
                    # find src near sink in code
                    if src in body and sink in body:
                        findings.append({"source":src,"sink":sink,"file":ju or "inline"})
                        print(f"  [!] {src} -> {sink} in {ju or 'inline'}")
                        logger.finding("xss_dom","high",f"{src} -> {sink}")

        # test hash with payload
        print("[xss_dom] testing hash injection")
        test_url = target.rstrip("/") + "/#" + '<img src=x onerror=alert(1)>'
        r2 = http.get(test_url)
        if r2 and "onerror" in r2.text:
            logger.finding("xss_dom_hash","high","payload reflected in HTML")

        print(f"[xss_dom] {len(findings)} DOM sources/sinks pairs")
        return {"findings": findings}
