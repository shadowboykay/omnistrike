"""tech_fingerprint — detect CMS, frameworks, servers from headers + html"""
import re
from core.http import HttpClient

HEADER_HINTS = {
    "Server": ["nginx","apache","iis","caddy","litespeed","openresty"],
    "X-Powered-By": ["php","asp.net","express","next.js","nuxt"],
    "X-Generator": ["wordpress","drupal","joomla"],
    "X-Drupal-Cache": ["drupal"],
    "X-Shopify-Stage": ["shopify"],
}
HTML_HINTS = {
    "WordPress": ["/wp-content/","/wp-includes/","wp-json"],
    "Drupal":    ["drupal.js","sites/default/files"],
    "Joomla":    ["/components/com_","joomla"],
    "React":     ["__react","data-reactroot","_next/static"],
    "Vue":       ["__vue__","data-v-"],
    "Angular":   ["ng-version","ng-app"],
    "jQuery":    ["jquery"],
    "Bootstrap": ["bootstrap.min.css","bootstrap.min.js"],
    "Nginx":     ["nginx"],
    "Cloudflare":["cf-ray","cloudflare"],
}

class TechFingerprint:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        r = http.get(session.target)
        if not r: return {"tech": []}
        tech = set()
        for h, keys in HEADER_HINTS.items():
            val = r.headers.get(h, "").lower()
            for k in keys:
                if k in val: tech.add(k)
        body = r.text.lower()
        for name, keys in HTML_HINTS.items():
            if any(k in body for k in keys): tech.add(name)
        for t in sorted(tech):
            print(f"  [+] {t}")
            logger.finding("tech", "info", t)
        return {"tech": sorted(tech), "server": r.headers.get("Server","")}
