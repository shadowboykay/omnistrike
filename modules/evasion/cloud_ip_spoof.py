"""cloud_ip_spoof — try cloud-provider IP ranges via public proxies/relays"""
from core.http import HttpClient


# public cloud HTTP relays (Cloudflare Workers, Vercel, Netlify)
CLOUD_RELAYS = [
    ("cloudflare_workers", "https://cloudflare.com/cdn-cgi/trace"),
    ("vercel_edge", "https://vercel.com/api/edge-check"),
    ("netlify_edge", "https://netlify.com/.netlify/functions/echo"),
    ("fastly_edge", "https://fastly.com/api/edge"),
]

# known cloud IP ranges for outbound proxy headers
CLOUD_IP_RANGES = {
    "aws_us_east": "3.",
    "aws_eu": "18.",
    "gcp": "34.",
    "azure": "20.",
    "cloudflare": "104.16.",
    "digitalocean": "104.236.",
    "linode": "96.126.",
}


class CloudIpSpoof:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        target = session.target

        # baseline
        base = http.get(target)
        base_code = base.status_code if base else None
        base_len = len(base.content) if base else 0
        print(f"[cloud_ip_spoof] baseline: {base_code} ({base_len}b)")

        results = []
        for name, prefix in CLOUD_IP_RANGES.items():
            spoofed_ip = prefix + str(random.randint(1, 254)) + "." + str(random.randint(1, 254))
            headers = {
                "X-Forwarded-For": spoofed_ip,
                "X-Real-IP": spoofed_ip,
                "CF-Connecting-IP": spoofed_ip,
                "True-Client-IP": spoofed_ip,
                "X-Client-IP": spoofed_ip,
            }
            r = http.get(target, headers=headers)
            if not r:
                continue
            diff = abs(len(r.content) - base_len)
            changed = r.status_code != base_code or diff > 200
            marker = "  [!]" if changed else "     "
            print(f"{marker} {name:14s} {spoofed_ip:18s} {r.status_code} diff={diff:+d}")
            results.append({"cloud": name, "ip": spoofed_ip,
                            "code": r.status_code, "changed": changed})
            if changed:
                logger.finding("cloud_ip_bypass", "medium",
                               f"{name} IP {spoofed_ip} changed response")

        print(f"[cloud_ip_spoof] {sum(1 for r in results if r['changed'])}/{len(results)} changed response")
        return {"results": results}
