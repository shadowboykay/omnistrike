#!/usr/bin/env python3
# test_all.py — full live test of all OmniStrike modules on legal targets
"""
Запускает все модули по очереди на легальных стендах.
Отчёт: что работает, что падает, что требует спец-цели.
"""
import sys, os, time, json, subprocess
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from core.loader import ModuleLoader
from core.session import Session
from core.logger import Logger


# Легальные цели для разных категорий
TARGETS = {
    "web": "http://testphp.vulnweb.com/artists.php?artist=1",
    "web_form": "http://testphp.vulnweb.com/search.php?test=query",
    "recon": "http://demo.testfire.net/",
    "subdomain": "example.com",
    "osint_username": "torvalds",
    "osint_domain": "example.com",
    "osint_ip": "1.1.1.1",
    "cloud": "https://flipkart.com",
    "template": "http://demo.testfire.net/",
}

# Модули с особыми требованиями (не тестируются автоматически)
SKIP_MODULES = {
    "web": ["sqli_post"],           # требует POST данных
    "recon": ["authenticated_scan"], # требует creds
    "osint": ["email", "phone", "dox"],  # требует конкретный target
    "mobile": ["apk_analyze", "apk_patch", "dex_decompile", "frida_hook", "ios_plist"],  # требует APK
    "c2": ["listener", "agent_builder", "beacon_dns"],  # требует запуска сервера
    "post": ["attack_graph", "defense_analyzer", "lateral", "persistence", "privesc_check", "loot", "cleanup", "diff_scan"],  # требует спец
    "ad": ["checklist", "ldap_enum"],  # требует LDAP сервер
    "dump": [],  # все можно
}


def test_module(cat, mod, target, timeout=60):
    """Run one module. Returns dict with result."""
    session = Session(target=target, timeout=8)
    logger = Logger(session)
    loader = ModuleLoader()
    m = loader.load(cat, mod)
    if not m:
        return {"status": "not_found", "error": None, "findings": 0, "time": 0}

    t0 = time.time()
    try:
        m.run(session, logger)
        dt = time.time() - t0
        return {
            "status": "ok",
            "error": None,
            "findings": len(session.findings),
            "time": round(dt, 2),
        }
    except KeyboardInterrupt:
        raise
    except Exception as e:
        dt = time.time() - t0
        return {
            "status": "error",
            "error": f"{type(e).__name__}: {str(e)[:100]}",
            "findings": len(session.findings),
            "time": round(dt, 2),
        }


def run_all(tag="full"):
    """Run all modules, save report."""
    loader = ModuleLoader()
    targets_by_cat = {
        "web": TARGETS["web"],
        "bypass": TARGETS["web"],
        "exploit": TARGETS["web"],
        "evasion": TARGETS["web"],
        "recon": TARGETS["recon"],
        "osint": TARGETS["osint_username"],
        "cloud": TARGETS["cloud"],
        "dump": TARGETS["web"],
        "template": TARGETS["template"],
    }

    results = {}
    total = 0
    ok = 0
    errors = 0
    skipped = 0

    # web, bypass, exploit, evasion, dump — на vulnweb
    cats_to_test = ["recon", "web", "bypass", "exploit", "evasion", "dump", "osint", "cloud", "ad", "mobile", "c2", "post"]

    for cat in cats_to_test:
        mods = loader.list_category(cat)
        if not mods:
            continue

        target = targets_by_cat.get(cat, TARGETS["web"])
        print(f"\n{'='*70}")
        print(f"  {cat.upper()} ({len(mods)} modules) — target: {target[:60]}")
        print(f"{'='*70}")

        for i, mod in enumerate(sorted(mods.keys()), 1):
            total += 1

            # skip list
            if cat in SKIP_MODULES and mod in SKIP_MODULES[cat]:
                skipped += 1
                results[f"{cat}/{mod}"] = {"status": "skipped", "reason": "requires_special_target"}
                print(f"  [{i:3d}] {mod:30s} SKIP (special target)")
                continue

            print(f"  [{i:3d}] {mod:30s} ", end="", flush=True)
            r = test_module(cat, mod, target)

            if r["status"] == "ok":
                ok += 1
                print(f"OK ({r['time']}s, {r['findings']} findings)")
            elif r["status"] == "error":
                errors += 1
                print(f"ERROR: {r['error']}")
            else:
                print(f"{r['status']}")

            results[f"{cat}/{mod}"] = r

    # save report
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = ROOT / "tests" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    report = out_dir / f"test_all_{ts}.json"

    summary = {
        "total": total,
        "ok": ok,
        "errors": errors,
        "skipped": skipped,
        "results": results,
        "timestamp": datetime.now().isoformat(),
    }
    report.write_text(json.dumps(summary, indent=2))

    print(f"\n{'='*70}")
    print(f"  РЕЗУЛЬТАТ")
    print(f"{'='*70}")
    print(f"  Всего:   {total}")
    print(f"  OK:      {ok}")
    print(f"  ERROR:   {errors}")
    print(f"  SKIP:    {skipped}")
    print(f"\n  Отчёт:   {report}")

    # список ошибок
    if errors:
        print(f"\n  Модули с ошибками:")
        for key, r in results.items():
            if r["status"] == "error":
                print(f"    ✗ {key}: {r['error']}")

    return summary


if __name__ == "__main__":
    run_all()
