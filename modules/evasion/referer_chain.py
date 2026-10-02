"""referer_chain v2 — realistic referer chains via internal navigation.

v1: 4 search engines одним запросом (легко детектится).
v2: многошаговая цепочка:
   Google search → main page → internal link → target

Плюс:
  - tracking cookies (_ga, _gid, _fbp)
  - правильные Sec-Fetch-Site headers
  - реалистичные тайминги между шагами
  - warmup mode (первый шаг — главная, потом navigation)

API для модулей:
    from modules.evasion.referer_chain import get_chain_referer
    referer, cookies = get_chain_referer(target_domain, target_url)
"""
import random
import time
from urllib.parse import urlparse
from core.http import HttpClient


# ==== search engines для начального referer ====
SEARCH_ENGINES = [
    ("google.com/search", "https://www.google.com/search?q={q}&oq={q}&aqs=chrome"),
    ("yandex.ru/search", "https://yandex.ru/search/?text={q}&lr=213"),
    ("bing.com/search", "https://www.bing.com/search?q={q}&form=QBLH"),
    ("duckduckgo.com", "https://duckduckgo.com/?q={q}&t=h_&ia=web"),
]


def _make_search_query(domain):
    """Реалистичный поисковый запрос — домен или бренд."""
    base = domain.replace("www.", "").split(".")[0]
    variants = [
        base,
        base + " официальный",
        base + " сайт",
        base + " login",
        base + " portal",
    ]
    return random.choice(variants).replace(" ", "+")


def _make_ga_cookies():
    """Реалистичные tracking cookies (формат Google Analytics)."""
    import secrets
    ga_id = "GA1.2." + str(random.randint(10**9, 10**10)) + "." + str(int(time.time()))
    gid = "GA1.2." + str(random.randint(10**9, 10**10)) + "." + str(int(time.time()))
    return {
        "_ga": ga_id,
        "_gid": gid,
        "_ga_" + secrets.token_hex(4).upper()[:4]: "GS1.1." + str(int(time.time())) + ".1.0.0.0",
    }


class RefererChain:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        u = urlparse(target)
        origin = f"{u.scheme}://{u.netloc}"
        domain = u.netloc

        # режим — warmup или direct
        mode = "warmup"
        for x in getattr(session, "extra", []) or []:
            if x.startswith("referer_mode="):
                mode = x[14:].strip()

        print(f"[referer_chain v2] target: {target}")
        print(f"[referer_chain v2] origin: {origin}")
        print(f"[referer_chain v2] mode: {mode}")

        findings = []
        steps = []

        # === 1. Начальная навигация — главная страница ===
        cookies = _make_ga_cookies()
        print()
        print(f"[referer_chain v2] Step 1: GET {origin}/ (fresh session)")

        headers_1 = {
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }
        # cookies set
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        headers_1["Cookie"] = cookie_str

        try:
            r1 = http.get(origin + "/", headers=headers_1)
            steps.append({"step": 1, "url": origin + "/",
                          "status": r1.status_code if r1 else 0,
                          "size": len(r1.content) if r1 else 0,
                          "referer": None})
        except Exception as e:
            print(f"  ERR: {e}")
            return {"findings": [], "steps": steps}

        time.sleep(random.uniform(1.0, 3.5))

        # === 2. Внутренний переход — со страницы на страницу ===
        # ищем ссылки на главной (для внутреннего Referer)
        internal_targets = []
        if r1 and r1.text:
            import re
            hrefs = re.findall(r'href=["\']([^"\']+)["\']', r1.text)
            for h in hrefs:
                if h.startswith("/") and not h.startswith("//"):
                    internal_targets.append(h)
                elif h.startswith(origin):
                    internal_targets.append(h[len(origin):] or "/")

        if internal_targets and mode == "warmup":
            pick = random.choice(internal_targets[:20])
            url_2 = origin + pick
            print(f"[referer_chain v2] Step 2: GET {url_2} (referer={origin}/)")

            headers_2 = {
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-User": "?1",
                "Referer": origin + "/",
                "Cookie": cookie_str,
            }
            try:
                r2 = http.get(url_2, headers=headers_2)
                steps.append({"step": 2, "url": url_2,
                              "status": r2.status_code if r2 else 0,
                              "size": len(r2.content) if r2 else 0,
                              "referer": origin + "/"})
                time.sleep(random.uniform(2.0, 6.0))
            except Exception:
                pass

        # === 3. Переход к целевой странице с внутренним Referer ===
        print(f"[referer_chain v2] Step 3: GET {target} (referer={steps[-1]['url'] if steps else origin})")

        inner_referer = steps[-1]["url"] if steps else origin + "/"
        headers_3 = {
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-User": "?1",
            "Referer": inner_referer,
            "Cookie": cookie_str,
        }

        try:
            r3 = http.get(target, headers=headers_3)
            steps.append({"step": 3, "url": target,
                          "status": r3.status_code if r3 else 0,
                          "size": len(r3.content) if r3 else 0,
                          "referer": inner_referer})
            print(f"  result: {r3.status_code if r3 else 'None'} ({len(r3.content) if r3 else 0}b)")
        except Exception as e:
            print(f"  ERR: {e}")

        # === 4. Прямой compare — какой Referer даёт лучший ответ ===
        print()
        print(f"[referer_chain v2] Comparing referer strategies:")

        strategies = []
        for name, tmpl in SEARCH_ENGINES[:2]:  # Google + Yandex
            q = _make_search_query(domain)
            referer = tmpl.format(q=q)
            h = {
                "Referer": referer,
                "Sec-Fetch-Site": "cross-site",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
            }
            try:
                r = http.get(target, headers=h)
                strategies.append({
                    "strategy": f"search:{name}",
                    "status": r.status_code if r else 0,
                    "size": len(r.content) if r else 0,
                })
                print(f"  search:{name:20s} → {r.status_code if r else 'None'} ({len(r.content) if r else 0}b)")
            except Exception:
                pass

        # Google cache referer
        cache_referer = f"https://webcache.googleusercontent.com/search?q=cache:{domain}"
        try:
            r = http.get(target, headers={"Referer": cache_referer})
            strategies.append({"strategy": "google_cache",
                               "status": r.status_code if r else 0,
                               "size": len(r.content) if r else 0})
            print(f"  google_cache              → {r.status_code if r else 'None'}")
        except Exception:
            pass

        print()
        print(f"[referer_chain v2] steps: {len(steps)}")

        logger.info("referer_chain",
                    steps=len(steps),
                    strategies=len(strategies))

        return {
            "findings": findings,
            "steps": steps,
            "strategies": strategies,
            "cookies_set": list(cookies.keys()),
        }
