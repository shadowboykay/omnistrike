"""dns v2 — record enumeration via DoH (bypass local resolver).

Записи: A, AAAA, MX, NS, TXT, SOA, CNAME, CAA, SRV, DNSKEY.
Плюс: wildcard detection, SPF/DMARC из TXT, zone transfer probe.

DoH (Cloudflare 1.1.1.1) — обходит локальные подмены (Huawei HiCure и т.п.).
"""
import json
import secrets
import urllib.request
from urllib.parse import urlparse


DOH_URL = "https://cloudflare-dns.com/dns-query"
DOH_GOOGLE = "https://dns.google/resolve"

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA", "SRV", "DNSKEY"]


def _doh_query(domain, rtype, provider="cf", timeout=8):
    """DoH запрос через Cloudflare или Google. Возвращает list of data strings."""
    if provider == "cf":
        url = DOH_URL + "?name=" + domain + "&type=" + rtype
    else:
        url = DOH_GOOGLE + "?name=" + domain + "&type=" + rtype
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
        return data.get("Answer", []) or [], data.get("Status", 0)
    except Exception as e:
        return [], -1


def _extract_host(target):
    """Возвращает hostname из target (url или host)."""
    if "://" in target:
        u = urlparse(target)
        return u.hostname or ""
    return target.split("/")[0].split(":")[0]


class DNS:
    def run(self, session, logger):
        host = _extract_host(session.target)
        if not host:
            print("[dns v2] cannot extract host from target")
            return {}

        print("[dns v2] target: " + host)
        print("[dns v2] resolver: Cloudflare DoH (1.1.1.1)")
        print()

        out = {}
        # --- main records ---
        for rtype in RECORD_TYPES:
            answers, status = _doh_query(host, rtype)
            if status != 0 or not answers:
                out[rtype] = []
                continue
            values = [a.get("data") for a in answers if a.get("type") == _type_num(rtype)]
            out[rtype] = values
            if values:
                print("  " + rtype + ":")
                for v in values[:10]:
                    print("    " + str(v)[:120])
                if len(values) > 10:
                    print("    ... and " + str(len(values) - 10) + " more")

        # --- SPF / DMARC extraction from TXT ---
        spf = [t for t in out.get("TXT", []) if "v=spf1" in t]
        dmarc_txt, _ = _doh_query("_dmarc." + host, "TXT")
        dmarc = [a.get("data") for a in dmarc_txt if "v=DMARC1" in str(a.get("data", ""))]

        if spf:
            print()
            print("  SPF: " + spf[0][:150])
        if dmarc:
            print("  DMARC: " + dmarc[0][:150])

        # --- wildcard detection ---
        print()
        rnd = secrets.token_hex(8) + "." + host
        wc_answers, wc_status = _doh_query(rnd, "A")
        wildcard = wc_status == 0 and bool(wc_answers)
        if wildcard:
            print("[dns v2] WILDCARD detected: *." + host + " resolves")
            out["wildcard"] = True
        else:
            out["wildcard"] = False

        # --- zone transfer probe (AXFR) — quick, via ns servers ---
        ns_servers = out.get("NS", [])
        axfr_results = []
        for ns in ns_servers[:2]:
            ns_host = str(ns).rstrip(".")
            try:
                # AXFR требует TCP + специальный запрос — упрощённый probe через dig-подобный HTTP-запрос не работает
                # пробуем tcp connect на 53 порт
                import socket as _sock
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                s.settimeout(3)
                ip = _sock.gethostbyname(ns_host)
                s.connect((ip, 53))
                s.close()
                # TCP доступен — теоретически AXFR возможен, но full AXFR через http невозможен
                axfr_results.append({"ns": ns_host, "tcp53": True})
            except Exception:
                axfr_results.append({"ns": ns_host, "tcp53": False})
        if axfr_results:
            print()
            print("  NS servers (TCP/53):")
            for r in axfr_results:
                print("    " + r["ns"] + " tcp53=" + str(r["tcp53"]))

        # --- CAA + DNSKEY check (security hygiene) ---
        if not out.get("CAA"):
            print()
            print("  CAA: (none) — no restriction on certificate authorities")
        if not out.get("DNSKEY"):
            print("  DNSKEY: (none) — DNSSEC not configured")

        # --- summary + logger ---
        summary = {k: len(v) if isinstance(v, list) else v for k, v in out.items()}
        print()
        print("[dns v2] summary: " + json.dumps(summary))

        try:
            logger.info("dns_done", records=summary)
        except Exception:
            pass

        # finding если wildcard или нет CAA/DMARC
        try:
            if wildcard:
                logger.finding("dns_wildcard", "info",
                               "wildcard *." + host + " — subdomain enum unreliable")
            if not dmarc:
                logger.finding("dns_no_dmarc", "info",
                               "no DMARC record for " + host)
        except Exception:
            pass

        return out


def _type_num(rtype):
    """Маппинг имени к числовому type в DNS-ответе."""
    return {
        "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15,
        "TXT": 16, "AAAA": 28, "SRV": 33, "CAA": 257, "DNSKEY": 48,
    }.get(rtype, 0)
