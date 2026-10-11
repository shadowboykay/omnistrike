"""email_harvest v2 — emails from pages + mailto + security.txt + RDAP + robots/sitemap.

Источники:
  1. 20 стандартных страниц (was 12): /, /contact, /about, /team, /support,
     /help, /company, /impressum, /privacy, /terms, /careers, /jobs,
     /security, /legal, /press, /media, /partners, /investors,
     /contact-us, /about-us
  2. mailto: ссылки
  3. /.well-known/security.txt + /security.txt (security@ email)
  4. RDAP lookup — abuse contact регистратора (через DoH)
  5. robots.txt + sitemap.xml
  6. Cross-domain: собирать все, но разделять "same domain" и "external"

Фильтр мусора:
  - example.com, localhost, test@, noreply@
  - CDN-домены: sentry.io, wixpress.com, google-analytics.com
  - Графические ложные (image@2x.png)

Классификация ролей:
  - critical: security@, abuse@, admin@, root@
  - high: support@, sales@, hr@, finance@, billing@
  - normal: info@, contact@, hello@
  - personal: name.surname@ (без роли)
"""
import re
import json
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.http import HttpClient


PAGES = [
    "/", "/contact", "/contact-us", "/about", "/about-us",
    "/team", "/support", "/help", "/company",
    "/impressum", "/privacy", "/terms", "/careers", "/jobs",
    "/security", "/legal", "/press", "/media",
    "/partners", "/investors",
]

SECURITY_TXT_PATHS = [
    "/.well-known/security.txt",
    "/security.txt",
]

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
MAILTO_RE = re.compile(r"mailto:([^\"'>?\s]+)")

# шум от CDN и служебных доменов
NOISE_DOMAINS = [
    "example.com", "example.org", "example.net",
    "localhost", "test.local",
    "sentry.io", "sentry-cdn.com", "wixpress.com",
    "google-analytics.com", "googletagmanager.com",
    "doubleclick.net", "facebook.com", "twitter.com",
    "cloudflare.com", "cloudfront.net",
    "w3.org", "schema.org", "sentry.wixpress.com",
]

# шумовые префиксы
NOISE_PREFIXES = [
    "noreply@", "no-reply@", "donotreply@", "mailer-daemon@",
    "postmaster@", "bounce@", "bounces@", "notifications@",
]

# роли
ROLE_CLASSIFICATION = {
    "critical": ["security@", "abuse@", "admin@", "root@", "ciso@", "soc@"],
    "high": ["support@", "sales@", "hr@", "finance@", "billing@",
             "legal@", "compliance@"],
    "normal": ["info@", "contact@", "hello@", "team@", "office@",
               "enquiries@", "inquiries@"],
}


def _extract_domain(target):
    if "://" in target:
        u = urllib.parse.urlparse(target)
        return u.hostname or ""
    return target.split("/")[0].split(":")[0]


def _is_noise(email):
    e = email.lower()
    if any(nd in e for nd in NOISE_DOMAINS):
        return True
    if any(e.startswith(np) for np in NOISE_PREFIXES):
        return True
    if re.search(r"\.(png|jpg|jpeg|gif|webp|svg|woff|woff2|ttf|ico)$", e):
        return True
    if "@2x" in e or "@3x" in e or "@1x" in e:
        return True
    # слишком короткое или мусорное
    if len(e) < 6 or len(e) > 100:
        return True
    return False


def _classify(email):
    e = email.lower()
    for cat, prefixes in ROLE_CLASSIFICATION.items():
        for p in prefixes:
            if e.startswith(p):
                return cat
    return "personal"


def _rdap_abuse_email(domain, timeout=8):
    """RDAP lookup — abuse email регистратора."""
    try:
        # determine RIR (упрощённо — .com/.net/.org через ARIN)
        tld = domain.rsplit(".", 1)[-1].lower()
        rir_map = {
            "com": "https://rdap.verisign.com/com/v1/domain/",
            "net": "https://rdap.verisign.com/net/v1/domain/",
            "org": "https://rdap.publicinterestregistry.org/rdap/domain/",
            "io":  "https://rdap.identitydigital.services/rdap/domain/",
            "co":  "https://rdap.nic.co/domain/",
            "de":  "https://rdap.denic.de/domain/",
            "ru":  "https://rdap.tcinet.ru/domain/",
            "ua":  "https://rdap.net.ua/domain/",
        }
        rir = rir_map.get(tld)
        if not rir:
            return None
        req = urllib.request.Request(rir + domain,
                                     headers={"Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
        # ищем abuse email в entities
        for ent in data.get("entities", []):
            for role in ent.get("roles", []):
                if role in ("abuse", "registrant", "technical", "administrative"):
                    for vcard in (ent.get("vcardArray") or [None, []])[1]:
                        if len(vcard) >= 4 and vcard[0] == "email":
                            return vcard[3]
        return None
    except Exception:
        return None


def _fetch_security_txt(http, base):
    """Извлекает security@ email из security.txt."""
    emails = set()
    for path in SECURITY_TXT_PATHS:
        try:
            r = http.get(base + path)
        except Exception:
            continue
        if not r or r.status_code != 200:
            continue
        text = r.text or ""
        emails.update(EMAIL_RE.findall(text))
    return emails


class EmailHarvest:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        u = urllib.parse.urlparse(base)
        origin = u.scheme + "://" + u.netloc if u.scheme else base
        domain = _extract_domain(session.target)
        http = HttpClient(session, logger)

        print("[email v2] target: " + base)
        print("[email v2] domain: " + domain)

        emails = set()

        # === 1. common pages ===
        def scrape(path):
            try:
                r = http.get(base + path)
            except Exception:
                return set()
            if not r or r.status_code != 200:
                return set()
            text = r.text or ""
            found = set(EMAIL_RE.findall(text))
            found |= set(MAILTO_RE.findall(text))
            return found

        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(scrape, p) for p in PAGES]
            for f in as_completed(futs):
                try:
                    emails |= f.result()
                except Exception:
                    pass

        print("[email v2] from pages: " + str(len(emails)))

        # === 2. security.txt ===
        sec_emails = _fetch_security_txt(http, origin)
        if sec_emails:
            print("[email v2] from security.txt: " + str(len(sec_emails)))
            emails |= sec_emails

        # === 3. robots.txt ===
        try:
            rb = http.get(origin + "/robots.txt")
            if rb and rb.status_code == 200:
                rb_emails = set(EMAIL_RE.findall(rb.text or ""))
                if rb_emails:
                    print("[email v2] from robots.txt: " + str(len(rb_emails)))
                    emails |= rb_emails
        except Exception:
            pass

        # === 4. RDAP abuse ===
        abuse = _rdap_abuse_email(domain)
        if abuse:
            print("[email v2] RDAP abuse: " + abuse)
            emails.add(abuse)

        # === 5. filter noise ===
        emails = {e for e in emails if not _is_noise(e)}
        emails = {e.lower() for e in emails}

        # === 6. classify ===
        classified = {"critical": [], "high": [], "normal": [], "personal": []}
        same_domain = []
        external = []

        for e in sorted(emails):
            cat = _classify(e)
            classified[cat].append(e)
            if e.endswith("@" + domain.lower()):
                same_domain.append(e)
            else:
                external.append(e)

        # === 7. output ===
        print()
        print("[email v2] found " + str(len(emails)) + " unique emails")
        print("  same-domain: " + str(len(same_domain)) + ", external: " + str(len(external)))
        print("  roles: critical=" + str(len(classified["critical"])) +
              " high=" + str(len(classified["high"])) +
              " normal=" + str(len(classified["normal"])) +
              " personal=" + str(len(classified["personal"])))

        if classified["critical"]:
            print()
            print("[email v2] CRITICAL roles:")
            for e in classified["critical"][:10]:
                print("  " + e)

        if same_domain:
            print()
            print("[email v2] same-domain emails (first 20):")
            for e in same_domain[:20]:
                print("  " + e)

        # === 8. findings ===
        try:
            if emails:
                logger.finding("email_harvest_summary", "info",
                               domain + ": " + str(len(emails)) + " emails, " +
                               str(len(same_domain)) + " same-domain")
            for e in classified["critical"][:5]:
                logger.finding("email_critical_role", "medium", e)
            for e in same_domain[:20]:
                logger.finding("email_same_domain", "info", e)
        except Exception:
            pass

        print()
        print("[email v2] findings: " + str(len(emails)))

        return {
            "emails": sorted(emails),
            "same_domain": same_domain,
            "external": external,
            "classified": classified,
        }
