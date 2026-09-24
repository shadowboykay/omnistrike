"""wpscan_lite — WordPress quick scan: version, users, plugins, readme, xmlrpc"""
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.http import HttpClient

PLUGINS = ["akismet","contact-form-7","wordpress-seo","woocommerce","elementor","jetpack",
           "all-in-one-seo-pack","wordfence","wpforms-lite","really-simple-ssl","classic-editor",
           "wp-super-cache","w3-total-cache","litespeed-cache","advanced-custom-fields",
           "wp-mail-smtp","duplicator","updraftplus","backupwordpress","redirection",
           "google-analytics-for-wordpress","instagram-feed","wp-statistics","wp-rocket",
           "nextgen-gallery","revslider","layer-slider","essential-addons-for-elementor"]

class WpscanLite:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        info = {"version": None, "users": [], "plugins": [], "xmlrpc": False, "readme": False}

        # version from readme / meta / feed
        for path in ["/readme.html","/wp-includes/version.php","/?feed=rss2"]:
            r = http.get(base + path)
            if not r or r.status_code != 200: continue
            m = re.search(r"Version\s+([\d.]+)", r.text)
            if m:
                info["version"] = m.group(1)
                print(f"  [+] version: {m.group(1)}")
                logger.finding("wp_version","info",m.group(1))
                break

        if info["version"] is None:
            r = http.get(base)
            if r:
                m = re.search(r'content="WordPress ([\d.]+)"', r.text)
                if m: info["version"] = m.group(1)

        # readme
        r = http.get(base + "/readme.html")
        info["readme"] = bool(r and r.status_code == 200 and "wordpress" in r.text.lower())

        # xmlrpc
        r = http.post(base + "/xmlrpc.php", data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>')
        if r and "methodResponse" in r.text:
            info["xmlrpc"] = True
            print("  [+] xmlrpc.php enabled")
            logger.finding("wp_xmlrpc","medium","xmlrpc.php enabled (brute amplification)")

        # users via REST
        r = http.get(base + "/wp-json/wp/v2/users")
        if r and r.status_code == 200:
            try:
                for u in r.json():
                    info["users"].append(u.get("slug"))
                    print(f"  [+] user: {u.get('slug')}")
                    logger.finding("wp_user","info",u.get("slug"))
            except Exception: pass

        # plugins
        def check_plugin(p):
            r = http.get(f"{base}/wp-content/plugins/{p}/readme.txt")
            if r and r.status_code == 200:
                m = re.search(r"Stable tag:\s*([\d.]+)", r.text)
                return p, m.group(1) if m else None
            return None

        with ThreadPoolExecutor(max_workers=15) as ex:
            futs = [ex.submit(check_plugin, p) for p in PLUGINS]
            for f in as_completed(futs):
                res = f.result()
                if res:
                    p, ver = res
                    info["plugins"].append({"name":p,"version":ver})
                    print(f"  [+] plugin: {p} {ver or ''}")
                    logger.finding("wp_plugin","medium",f"{p} {ver or '?'}")

        print(f"[wpscan_lite] version={info['version']} users={len(info['users'])} plugins={len(info['plugins'])}")
        return info
