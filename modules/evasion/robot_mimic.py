"""robot_mimic — mimic SEO crawlers (often whitelisted by WAF)"""
from core.http import HttpClient


ROBOTS = {
    "semrush": {
        "User-Agent": "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
    },
    "ahrefs": {
        "User-Agent": "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    },
    "mj12": {
        "User-Agent": "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)",
    },
    "screaming_frog": {
        "User-Agent": "Screaming Frog SEO Spider/19.2",
    },
    "dotbot": {
        "User-Agent": "Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)",
    },
    "petalbot": {
        "User-Agent": "Mozilla/5.0 (compatible;PetalBot;+https://webmaster.petalsearch.com/site/petalbot)",
    },
    "bytespider": {
        "User-Agent": "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)",
    },
    "bing_preview": {
        "User-Agent": "Mozilla/5.0 (compatible; BingPreview/1.0b; +https://www.bing.com/bingbot.htm)",
    },
    "google_site_verifier": {
        "User-Agent": "Mozilla/5.0 (compatible; Google-Site-Verification/1.0)",
    },
}


class RobotMimic:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        base = http.get(session.target)
        base_code = base.status_code if base else None
        base_len = len(base.content) if base else 0

        results = []
        for name, headers in ROBOTS.items():
            r = http.get(session.target, headers=headers)
            if not r:
                continue
            diff = abs(len(r.content) - base_len)
            changed = r.status_code != base_code or diff > 200
            marker = "  [!]" if changed else "     "
            print(f"{marker} {name:20s} {r.status_code} ({len(r.content)}b, diff {diff:+d})")
            results.append({"robot": name, "code": r.status_code, "diff": diff,
                            "changed": changed})
            if changed:
                logger.finding("robot_bypass", "medium",
                               f"{name} -> {r.status_code} diff={diff}")

        changed_count = sum(1 for r in results if r["changed"])
        print(f"[robot_mimic] {changed_count}/{len(results)} get different response")
        return {"results": results}
