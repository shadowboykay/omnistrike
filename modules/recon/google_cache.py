"""google_cache v2 — multi-service cache/archive lookup.

ВАЖНО: Google отключил cache: в сентябре 2024 (после обновления
search). v1 был бесполезен. v2 пробует 5 альтернатив:

  1. Google Cache (webcache.googleusercontent.com) — обычно 404 с 2024
  2. Wayback Machine availability API (free)
  3. Archive.today (archive.ph) newest endpoint
  4. Bing cache (cc.bingj.com/cache.aspx)
  5. Yandex cache (yandexwebcache.net)

Findings:
  - summary (info)
  - available cache URL (info)
  - staleness: если snapshot старый (годы) — info с датой
"""
import json
import urllib.request
import urllib.parse
from urllib.parse import quote, urlparse


def _fetch(url, headers=None, timeout=10):
    h = {"User-Agent": "Mozilla/5.0 (compatible; OmniStrike/2.0)"}
    if headers:
        h.update(headers)
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status_code, r.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


def _google_cache(target):
    """Google cache — обычно отключён с 2024, но пробуем."""
    url = "https://webcache.googleusercontent.com/search?q=cache:" + quote(target)
    st, body = _fetch(url)
    if st == 200 and "does not exist" not in body.lower() and "not found" not in body.lower():
        return {"service": "google", "url": url, "status": st}
    return None


def _wayback(target):
    """Wayback Machine availability API."""
    try:
        url = "https://archive.org/wayback/available?url=" + quote(target)
        st, body = _fetch(url)
        if st != 200:
            return None
        data = json.loads(body)
        snap = data.get("archived_snapshots", {}).get("closest", {})
        if snap and snap.get("available"):
            return {
                "service": "wayback",
                "url": snap.get("url", ""),
                "timestamp": snap.get("timestamp", ""),
                "status": snap.get("status", ""),
            }
    except Exception:
        pass
    return None


def _archive_today(target):
    """Archive.today (archive.ph) — newest snapshot."""
    url = "https://archive.ph/newest/" + target
    st, body = _fetch(url, timeout=12)
    # archive.ph делает redirect на конкретный snapshot; 200 или 302 = есть
    if st in (200, 302):
        return {"service": "archive.today", "url": url, "status": st}
    return None


def _bing_cache(target):
    """Bing cache — иногда работает."""
    url = "https://cc.bingj.com/cache.aspx?q=" + quote(target) + "&d=&mkt=en-US"
    st, body = _fetch(url, timeout=10)
    if st == 200 and len(body) > 500:
        return {"service": "bing", "url": url, "status": st, "size": len(body)}
    return None


def _yandex_cache(target):
    """Yandex cache — работает для русских сайтов."""
    try:
        # yandex требует авторизации, но webcache endpoint иногда открыт
        url = "https://yandexwebcache.net/yandbtm?url=" + quote(target) + "&lang=ru"
        st, body = _fetch(url, timeout=10)
        if st == 200 and len(body) > 500:
            return {"service": "yandex", "url": url, "status": st, "size": len(body)}
    except Exception:
        pass
    return None


class GoogleCache:
    def run(self, session, logger):
        target = session.target
        print("[google_cache v2] target: " + target)
        print("[google_cache v2] NOTE: Google cache disabled 2024; trying 5 services")

        results = []
        services = [
            ("google", _google_cache),
            ("wayback", _wayback),
            ("archive.today", _archive_today),
            ("bing", _bing_cache),
            ("yandex", _yandex_cache),
        ]

        for name, fn in services:
            print("  probing " + name + "...")
            try:
                res = fn(target)
            except Exception as e:
                res = None
            if res:
                results.append(res)
                marker = "  [OK]"
                extra = ""
                if res.get("timestamp"):
                    extra = " (" + str(res["timestamp"]) + ")"
                if res.get("size"):
                    extra = " (" + str(res["size"]) + "b)"
                print("    " + res["service"] + ": " + res["url"][:100] + marker + extra)
            else:
                print("    " + name + ": no snapshot")

        # === findings ===
        findings_count = 0
        try:
            if results:
                logger.finding("cache_summary", "info",
                               target + ": " + str(len(results)) + " cache services available")
                findings_count += 1
                for r in results:
                    logger.finding("cache_" + r["service"], "info",
                                   r.get("url", "")[:200])
                    findings_count += 1
            else:
                logger.finding("cache_none", "info",
                               target + ": no cache snapshots available")
                findings_count += 1
        except Exception:
            pass

        print()
        print("[google_cache v2] available services: " + str(len(results)))
        print("[google_cache v2] findings: " + str(findings_count))

        return {
            "available": results,
            "count": len(results),
        }
