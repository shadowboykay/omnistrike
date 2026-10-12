#!/usr/bin/env python3
# omni_menu.py — full interactive menu for OmniStrike v2
import sys, os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from core.loader import ModuleLoader
from core.session import Session
from core.logger import Logger
from core.report import Reporter
from core.spread import attach as spread_attach
from core.pipeline import CHAINS, run_chain


CATEGORIES = ["recon","web","bypass","exploit","evasion","c2","post",
              "osint","mobile","cloud","ad","dump"]


def clear():
    os.system("clear" if os.name != "nt" else "cls")


def banner():
    print("=" * 60)
    print("  OmniStrike v2 — интерактивное меню")
    print("=" * 60)


def ask(prompt, default=None):
    val = input(prompt).strip()
    if not val and default is not None:
        return default
    return val


# ============ MAIN MENU ============

def menu_main():
    while True:
        clear()
        banner()
        print("  АТАКИ:")
        print("   1. Одна атака (выбрать модуль)")
        print("   2. Цепочка (chain)")
        print("   3. Adaptive (recon → теги → атаки)")
        print("   4. Sniper mode (низкий шум)")
        print("   5. Список всех модулей")
        print("   6. Список цепочек")
        print()
        print("  РАЗВЕДКА И FINGERPRINT:")
        print("   7. Tech fingerprint (server/CMS/framework)")
        print("   8. Subdomain full (crt.sh + dns_history + urlscan + DoH)")
        print("   9. HTTP audit (headers + cookie + CSP)")
        print("  10. API discovery (api_hunter + swagger + api_leak)")
        print("  11. CVE-скан (по fingerprint)")
        print("  12. Template scan (Nuclei)")
        print("  13. Template scan v2 (raw/dsl)")
        print()
        print("  WAF / ЗАЩИТА:")
        print("  14. WAF audit (detect + evasion)")
        print("  15. Аудит защиты (security_audit)")
        print("  16. CIS Compliance check")
        print("  17. Chameleon (детект WAF/honeypot)")
        print()
        print("  ИНСТРУМЕНТЫ:")
        print("  18. Payload lab (лаборатория)")
        print("  19. Authenticated scan (с кредами)")
        print("  20. Agent (автономное планирование)")
        print("  21. Swarm (50 идентичностей)")
        print("  22. Defense analysis (что видит SOC)")
        print("  23. Payload library stats")
        print()
        print("  СЕТЬ / ПРОКСИ:")
        print("  24. Прокси: обновить список")
        print("  25. Прокси: показать рабочие")
        print("  26. Tor: проверить")
        print("  27. Proxy server (Burp-lite)")
        print("  28. Templates: скачать все (Nuclei)")
        print("  29. Wordlists: скачать SecLists")
        print()
        print("  ОТЧЁТЫ:")
        print("  30. SARIF report (GitHub Security tab)")
        print("  31. Diff сканов (что изменилось)")
        print("  32. Webhook notify (Slack/Discord/Telegram)")
        print("  33. PDF report (последний скан)")
        print("  34. Report cleanup (удалить старые)")
        print()
        print("  МЕТА:")
        print("  35. Verification stats (baseline/verify)")
        print("  36. Wordlists: показать доступные")
        print("  37. Wordlists: скачать конкретный")
        print("  38. Live tests (test_all.py)")
        print()
        print("   0. Выход")
        print()
        c = ask("Выбор [0-38]: ")

        actions = {
            "1":  menu_run_module,
            "2":  menu_chain,
            "3":  menu_adaptive,
            "4":  menu_sniper_mode,
            "5":  menu_list,
            "6":  menu_chains_list,
            "7":  menu_fingerprint,
            "8":  menu_subdomain_full,
            "9":  menu_http_audit,
            "10": menu_api_discovery,
            "11": menu_cve_scan,
            "12": menu_template_scan,
            "13": menu_template_scan_v2,
            "14": menu_waf_audit,
            "15": menu_audit,
            "16": menu_compliance,
            "17": menu_chameleon,
            "18": menu_payload_lab,
            "19": menu_auth_scan,
            "20": menu_agent,
            "21": menu_swarm,
            "22": menu_defense,
            "23": menu_payload_stats,
            "24": menu_proxy_update,
            "25": menu_proxy_show,
            "26": menu_tor,
            "27": menu_proxy_server,
            "28": menu_download_templates,
            "29": menu_download_wordlists,
            "30": menu_sarif,
            "31": menu_diff,
            "32": menu_webhook,
            "33": menu_pdf_last,
            "34": menu_report_cleanup,
            "35": menu_verify_stats,
            "36": menu_wordlists_show,
            "37": menu_wordlist_download,
            "38": menu_live_tests,
        }

        if c == "0":
            break
        elif c in actions:
            actions[c]()
        else:
            input("Неверно. Enter...")



# ============ BASIC ============

def menu_run_module():
    clear(); banner()
    print("Категория:")
    for i, cat in enumerate(CATEGORIES, 1):
        print(f"  {i:2d}. {cat}")
    print()
    c = ask("Номер категории: ")
    try:
        cat = CATEGORIES[int(c) - 1]
    except (ValueError, IndexError):
        return

    loader = ModuleLoader()
    mods = loader.list_category(cat)
    if not mods:
        input("Нет модулей. Enter...")
        return

    clear(); banner()
    print(f"Модули в {cat}:")
    names = sorted(mods.keys())
    for i, m in enumerate(names, 1):
        print(f"  {i:2d}. {m:28s} {mods[m][:50]}")
    print()
    c = ask("Номер модуля: ")
    try:
        mod = names[int(c) - 1]
    except (ValueError, IndexError):
        return

    target = ask("Target (URL/IP): ")
    if not target:
        return

    extra = []
    if cat == "web" and "post" in mod:
        post = ask("POST данные (uid=1&passw=1): ")
        if post: extra.append(f"post={post}")

    proxy = ask("Proxy (Enter — нет): ")
    spread = ask("Автораспространение? [y/N]: ").lower() == "y"
    pause = ask("Пауза после находки? [y/N]: ").lower() == "y"

    clear(); banner()
    print(f"Запуск: {cat}/{mod} -> {target}")
    print("-" * 60)

    module = loader.load(cat, mod)
    if not module:
        input("Модуль не найден. Enter...")
        return

    session = Session(target=target, proxy=proxy or None, timeout=10)
    logger = Logger(session)
    reporter = Reporter(session, logger)

    spread_engine = None
    if spread:
        spread_engine = spread_attach(session, logger, loader,
                                       pause_after_finding=pause)

    try:
        result = module.run(session, logger)
    except KeyboardInterrupt:
        print("\n[!] прервано")
        return
    except Exception as e:
        print(f"[!] {type(e).__name__}: {e}")
        return

    reporter.write(result)

    if spread_engine:
        print("\n[spread] summary:")
        for k, v in spread_engine.summary().items():
            print(f"  {k}: {v}")

    input("\nEnter для возврата...")


def menu_chain():
    clear(); banner()
    print("Цепочки:")
    for i, name in enumerate(["recon","web","bypass","evasion","cloud",
                              "osint","dump","exploit","full","extended","auto"], 1):
        print(f"  {i:2d}. {name}")
    print("   0. Назад")
    print()
    c = ask("Выбор: ")
    if c == "0": return
    chains = {str(i): n for i, n in enumerate(
        ["recon","web","bypass","evasion","cloud","osint","dump","exploit","full","extended","auto"], 1)}
    chain = chains.get(c)
    if not chain: return

    target = ask("Target: ")
    if not target: return
    proxy = ask("Proxy (Enter — нет): ")

    clear(); banner()
    print(f"Chain: {chain} -> {target}")
    print("=" * 60)

    try:
        session = run_chain(chain, target, proxy=proxy or None)
        print(f"\n[done] findings: {len(session.findings)}")
    except KeyboardInterrupt:
        print("\n[!] прервано")
    except Exception as e:
        print(f"[!] {e}")

    input("\nEnter...")


def menu_list():
    clear(); banner()
    loader = ModuleLoader()
    for cat in CATEGORIES:
        mods = loader.list_category(cat)
        print(f"\n=== {cat} ({len(mods)}) ===")
        for name, desc in sorted(mods.items()):
            print(f"  {name:28s} {desc[:60]}")
    input("\nEnter...")


def menu_chains_list():
    clear(); banner()
    for name, steps in CHAINS.items():
        n = len(steps) if steps else "auto"
        print(f"  {name:10s} — {n}")
    input("\nEnter...")


# ============ TOOLS ============

def menu_audit():
    target = ask("Target: ")
    if target:
        os.system(f"python omni.py run recon security_audit --target '{target}'")
    input("\nEnter...")


def menu_compliance():
    target = ask("Target: ")
    if target:
        os.system(f"python omni.py run recon compliance_check --target '{target}' --extra 'benchmark=cis_web'")
    input("\nEnter...")


def menu_cve_scan():
    target = ask("Target: ")
    if target:
        os.system(f"python omni.py run exploit cve_match --target '{target}' --timeout 30")
    input("\nEnter...")


def menu_template_scan():
    target = ask("Target: ")
    if not target: return
    sev = ask("Severity (critical,high,medium — Enter для critical,high): ") or "critical,high"
    limit = ask("Limit (Enter=200): ") or "200"
    os.system(f"python omni.py run web template_scan --target '{target}' --extra 'severity={sev}' --extra 'limit={limit}'")
    input("\nEnter...")


def menu_payload_lab():
    target = ask("Target: ")
    if not target: return
    ctx = ask("Контекст (sql/xss/path/cmd/template/... — Enter для списка): ")
    if ctx:
        os.system(f"python omni.py run web payload_lab --target '{target}' --extra 'context={ctx}'")
    else:
        os.system(f"python omni.py run web payload_lab --target '{target}'")
    input("\nEnter...")


def menu_auth_scan():
    target = ask("Target: ")
    if not target: return
    creds = ask("Creds (user:pass): ")
    if not creds: return
    os.system(f"python omni.py run recon authenticated_scan --target '{target}' --extra 'creds={creds}'")
    input("\nEnter...")


def menu_agent():
    target = ask("Target: ")
    if not target: return
    task = ask("Задача (recon/web_scan/critical_only — Enter для web_scan): ") or "web_scan"
    script = f'''
import sys
sys.path.insert(0, '.')
from core.session import Session
from core.logger import Logger
from core.agent_planner import run_agent
s = Session(target='{target}', timeout=10)
l = Logger(s)
run_agent(s, l, task='{task}')
'''
    os.system(f"python -c \"{script}\"")
    input("\nEnter...")


def menu_chameleon():
    target = ask("Target: ")
    if target:
        os.system(f"python omni.py run evasion chameleon_v2 --target '{target}'")
    input("\nEnter...")


def menu_swarm():
    target = ask("Target: ")
    if target:
        os.system(f"python omni.py run evasion swarm_mode_v3 --target '{target}'")
    input("\nEnter...")


def menu_defense():
    target = ask("Target: ")
    if target:
        os.system(f"python omni.py run post defense_analyzer --target '{target}'")
    input("\nEnter...")


# ============ NETWORK ============

def menu_proxy_update():
    clear(); banner()
    print("Обновление прокси (1-3 мин)...")
    os.system("python -c 'import sys; sys.path.insert(0, \".\"); from core.proxy_manager import update_all; update_all()'")
    input("\nEnter...")


def menu_proxy_show():
    clear(); banner()
    os.system("python -c 'import sys; sys.path.insert(0, \".\"); from core.proxy_manager import load_cache; w = load_cache(); print(f\"Working: {len(w)}\"); [print(f\"  {p}\") for p in w[:30]]'")
    input("\nEnter...")


def menu_tor():
    target = ask("Target через Tor (Enter — только проверка): ")
    if target:
        os.system(f"python omni.py run evasion tor_auto --target '{target}'")
    else:
        os.system(f"python omni.py run evasion tor_auto --target 'http://check.torproject.org/'")
    input("\nEnter...")


def menu_proxy_server():
    clear(); banner()
    port = ask("Порт (Enter=8080): ") or "8080"
    print(f"Запуск proxy на 127.0.0.1:{port}")
    print("Ctrl+C для остановки")
    print()
    os.system(f"python omni_proxy.py {port}")


def menu_download_templates():
    clear(); banner()
    print("Скачивание всех Nuclei шаблонов (~70 MB)...")
    os.system("python -c 'from core.template_full import download_full; download_full()'")
    input("\nEnter...")


def menu_download_wordlists():
    clear(); banner()
    print("Скачивание SecLists wordlists (~15 MB)...")
    os.system("python -c 'from core.wordlist_mgr import download_all; download_all()'")
    input("\nEnter...")


# ============ ENTRY ============

# ============ NEW: reports + analysis ============

def menu_sarif():
    clear(); banner()
    target = ask("Target (для проверки SARIF): ")
    if not target:
        return
    os.system(f"python omni.py run recon waf_detect --target '{target}' --sarif")
    print()
    import glob
    files = sorted(glob.glob("reports/*.sarif"), key=os.path.getmtime, reverse=True)
    if files:
        print(f"Последний SARIF: {files[0]}")
        print("Открой на github.com → Security → Code scanning")
    input("\nEnter...")


def menu_diff():
    clear(); banner()
    print("Сравнение двух сканов")
    print()
    old = ask("Путь к старому JSON (Enter — авто): ")
    new = ask("Путь к новому JSON (Enter — авто): ")

    if old and new:
        os.system(f"python -c \"from core.diff import diff_scans; diff_scans('{old}', '{new}')\"")
    else:
        os.system("python -c 'from core.diff import diff_latest_two; diff_latest_two()'")
    input("\nEnter...")


def menu_webhook():
    clear(); banner()
    print("Отправка результата в Slack/Discord/Telegram")
    print()
    print("  Через переменные окружения:")
    print("    export WEBHOOK_URL=https://hooks.slack.com/...")
    print("    export WEBHOOK_TYPE=slack  # slack/discord/telegram")
    print()
    url = ask("URL webhook (Enter — использовать env): ")
    msg = ask("Сообщение: ") or "OmniStrike scan complete"

    if url:
        os.system(f"python -c \"import os; os.environ['WEBHOOK_URL']='{url}'; from core.webhook import send; send('{msg}')\"")
    else:
        os.system("python -c 'from core.webhook import send; send()'")
    input("\nEnter...")


def menu_pdf_last():
    clear(); banner()
    import glob
    files = sorted(glob.glob("reports/*.html"), key=os.path.getmtime, reverse=True)
    if not files:
        print("Нет HTML-отчётов. Запусти скан с --pdf")
        input("Enter...")
        return
    latest = files[0]
    print(f"Последний HTML: {latest}")
    print()
    print("Открой в браузере телефона, потом Ctrl+P → Save as PDF")
    print()
    print("Или используй weasyprint (если установлен):")
    print(f"  weasyprint {latest} report.pdf")
    input("\nEnter...")


def menu_template_scan_v2():
    clear(); banner()
    target = ask("Target: ")
    if not target: return
    sev = ask("Severity (critical,high — Enter для critical): ") or "critical"
    limit = ask("Limit (Enter=500): ") or "500"
    print()
    print("Запуск template_scan с полным Nuclei движком...")
    os.system(f"python omni.py run web template_scan --target '{target}' --extra 'severity={sev}' --extra 'limit={limit}'")
    input("\nEnter...")


def menu_wordlists_show():
    clear(); banner()
    os.system("python -c 'from core.wordlist_mgr import list_available; import json; print(json.dumps(list_available(), indent=2))'")
    print()
    os.system("du -sh wordlists/ 2>/dev/null")
    input("\nEnter...")


def menu_wordlist_download():
    clear(); banner()
    from core.wordlist_mgr import WORDLISTS
    names = list(WORDLISTS.keys())
    for i, n in enumerate(names, 1):
        print(f"  {i:2d}. {n}")
    print()
    c = ask("Номер списка (Enter — все): ")
    if c:
        try:
            name = names[int(c) - 1]
            os.system(f"python -c \"from core.wordlist_mgr import download; download('{name}')\"")
        except (ValueError, IndexError):
            print("Неверно")
    else:
        os.system("python -c 'from core.wordlist_mgr import download_all; download_all()'")
    input("\nEnter...")


def menu_verify_stats():
    clear()
    banner()
    print("  VERIFICATION STATS — фильтр ложных сработок")
    print("=" * 60)
    print()

    from core.verify import stats, reset_stats
    s = stats()

    total = s["passed"] + s["filtered"]
    print(f"  Всего сигналов:   {total}")
    print(f"  ✓ passed:         {s['passed']}")
    print(f"  ✗ filtered:       {s['filtered']}")
    if total:
        rate = s["filtered"] / total * 100
        print(f"  Фильтр-рейт:      {rate:.1f}%")
    print()

    modules = s.get("modules", {})
    if not modules:
        print("  (статистики по модулям нет — запусти любой модуль с verify)")
    else:
        print("  По модулям:")
        print(f"  {'module':<20s} {'passed':>8s} {'filtered':>10s} {'rate':>8s}")
        print("  " + "-" * 50)
        for mod, m in sorted(modules.items()):
            p_cnt, f_cnt = m.get("passed", 0), m.get("filtered", 0)
            t = p_cnt + f_cnt
            rate = f_cnt / t * 100 if t else 0.0
            print(f"  {mod:<20s} {p_cnt:>8d} {f_cnt:>10d} {rate:>7.0f}%")
        print()

    print("  Действия:")
    print("    r. сбросить счётчик")
    print("    Enter — назад")
    choice = input("  > ").strip().lower()
    if choice == "r":
        reset_stats()
        print("  счётчик сброшен")
        input("  Enter...")




# ============ NEW 2026-10 ============

def menu_adaptive():
    target = ask("Target: ")
    if not target:
        return
    ro = ask("Recon-only (пассивно)? [y/N]: ").lower() == "y"
    flag = " --recon-only" if ro else ""
    os.system(f"python omni.py adaptive --target '{target}'{flag}")
    input("\nEnter...")


def menu_sniper_mode():
    """Sniper — минимальный шум, максимальная точность."""
    clear(); banner()
    print("  SNIPER MODE")
    print("  ==========")
    print("  Минимум запросов, высокая точность.")
    print()
    target = ask("Target: ")
    if not target:
        return
    mod = ask("Модуль (sqli / sqli_post / xss / lfi / ssrf / ssti) [sqli]: ") or "sqli"
    if mod in ("sqli", "xss", "lfi", "ssrf", "ssti"):
        os.system(f"python omni.py run web {mod} --target '{target}' --extra 'sniper=1' --timeout 15")
    elif mod == "sqli_post":
        post = ask("POST данные (uid=admin&passw=test): ")
        if post:
            os.system(f"python omni.py run web sqli_post --target '{target}' --extra 'post={post}' --extra 'sniper=1' --timeout 15")
    else:
        print(f"Неизвестный модуль: {mod}")
    input("\nEnter...")


def menu_fingerprint():
    """Tech fingerprint + favicon + cookie + CSP в одном прогоне."""
    clear(); banner()
    print("  FINGERPRINT (tech + favicon + cookie + CSP)")
    print("  ===========================================")
    target = ask("Target: ")
    if not target:
        return
    print()
    print(f"  [1/4] tech_fingerprint...")
    os.system(f"python omni.py run recon tech_fingerprint --target '{target}' --timeout 10 2>&1 | tail -15")
    print()
    print(f"  [2/4] favicon...")
    os.system(f"python omni.py run recon favicon --target '{target}' --timeout 10 2>&1 | tail -12")
    print()
    print(f"  [3/4] cookie...")
    os.system(f"python omni.py run web cookie --target '{target}' --timeout 10 2>&1 | tail -12")
    print()
    print(f"  [4/4] csp...")
    os.system(f"python omni.py run web csp --target '{target}' --timeout 10 2>&1 | tail -12")
    print()
    print("  Отчёты: reports/")
    input("\nEnter...")


def menu_subdomain_full():
    """4 источника поддоменов: crt.sh + dns_history + urlscan + DoH."""
    clear(); banner()
    print("  SUBDOMAIN FULL")
    print("  ==============")
    print("  crt.sh + dns_history + urlscan + subdomain_brute (DoH)")
    print()
    domain = ask("Domain (example.com): ")
    if not domain:
        return
    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
    print()
    print(f"  [1/4] crt_sh...")
    os.system(f"python omni.py run recon crt_sh --target 'http://{domain}/' --timeout 20 2>&1 | tail -15")
    print()
    print(f"  [2/4] dns_history (HackerTarget)...")
    os.system(f"python omni.py run recon dns_history --target 'http://{domain}/' --timeout 20 2>&1 | tail -15")
    print()
    print(f"  [3/4] urlscan...")
    os.system(f"python omni.py run recon urlscan --target 'http://{domain}/' --timeout 20 2>&1 | tail -15")
    print()
    print(f"  [4/4] subdomain_brute (DoH)...")
    os.system(f"python omni.py run recon subdomain_brute --target '{domain}' --timeout 20 2>&1 | tail -20")
    print()
    print("  Отчёты: reports/")
    input("\nEnter...")


def menu_http_audit():
    """Headers + cookie + CSP + server fingerprint — security hygiene check."""
    clear(); banner()
    print("  HTTP AUDIT — security hygiene")
    print("  =============================")
    target = ask("Target: ")
    if not target:
        return
    print()
    print(f"  [1/3] cookie flags (Secure/HttpOnly/SameSite)...")
    os.system(f"python omni.py run web cookie --target '{target}' --timeout 10 2>&1 | tail -12")
    print()
    print(f"  [2/3] CSP + missing security headers...")
    os.system(f"python omni.py run web csp --target '{target}' --timeout 10 2>&1 | tail -15")
    print()
    print(f"  [3/3] tech_fingerprint...")
    os.system(f"python omni.py run recon tech_fingerprint --target '{target}' --timeout 10 2>&1 | tail -12")
    print()
    input("\nEnter...")


def menu_api_discovery():
    """api_hunter + swagger + api_leak — все источники API."""
    clear(); banner()
    print("  API DISCOVERY")
    print("  =============")
    target = ask("Target: ")
    if not target:
        return
    print()
    print(f"  [1/3] api_hunter (HTML/JS mining + swagger + graphql)...")
    os.system(f"python omni.py run recon api_hunter --target '{target}' --timeout 25 2>&1 | tail -25")
    print()
    print(f"  [2/3] swagger (OpenAPI spec extraction)...")
    os.system(f"python omni.py run web swagger --target '{target}' --timeout 15 2>&1 | tail -15")
    print()
    print(f"  [3/3] api_leak (secrets in JS bundles)...")
    os.system(f"python omni.py run web api_leak --target '{target}' --timeout 15 2>&1 | tail -15")
    print()
    input("\nEnter...")


def menu_waf_audit():
    """WAF detect v3 + evasion v2 — полный аудит защиты."""
    clear(); banner()
    print("  WAF AUDIT — detect + evasion")
    print("  ============================")
    target = ask("Target: ")
    if not target:
        return
    print()
    print(f"  [1/2] waf_detect v3 (passive + active + behavioral + rate-limit)...")
    os.system(f"python omni.py run recon waf_detect --target '{target}' --timeout 15 2>&1 | tail -30")
    print()
    print(f"  [2/2] waf_evasion v2 (WAF-specific routing + mutation chain)...")
    waf = ask("WAF type (Cloudflare/Akamai/AWS WAF/Imperva/ModSecurity/Sucuri — Enter=auto): ") or ""
    extra = f" --extra 'waf={waf}'" if waf else ""
    os.system(f"python omni.py run bypass waf_evasion --target '{target}'{extra} --timeout 15 2>&1 | tail -25")
    print()
    input("\nEnter...")


def menu_payload_stats():
    """Статистика payload-библиотек."""
    clear(); banner()
    print("  PAYLOAD LIBRARY STATS")
    print("  =====================")
    print()

    # sniper
    try:
        from core.sniper_payloads import SNIPER_SQLI, GROUPS
        from collections import Counter
        print(f"  SQLi sniper (curated): {len(SNIPER_SQLI)}")
        by_type = Counter(p["type"] for p in SNIPER_SQLI)
        for t, c in sorted(by_type.items()):
            print(f"    {t:14s} {c:3d}")
        by_dbms = Counter(p["dbms"] for p in SNIPER_SQLI)
        print(f"  По СУБД:")
        for d, c in sorted(by_dbms.items()):
            print(f"    {d:14s} {c:3d}")
    except Exception as e:
        print(f"  sniper_payloads: ERROR {e}")

    print()

    # waf_bypass
    try:
        from core.waf_bypass import MUTATORS, mutate_content_type
        print(f"  WAF-мутации: {len(MUTATORS)}")
        for name, _ in MUTATORS:
            print(f"    {name}")
        ct = mutate_content_type()
        print(f"  Content-Type вариантов: {len(ct)}")
    except Exception as e:
        print(f"  waf_bypass: ERROR {e}")

    print()

    # payload_source
    try:
        from core.payload_source import CONTEXTS
        print(f"  Payload contexts: {len(CONTEXTS) if hasattr(CONTEXTS, '__len__') else 'N/A'}")
    except Exception as e:
        print(f"  payload_source: проверь вручную (core/payload_source.py)")

    print()

    # wordlists
    try:
        import os
        wl_dir = "wordlists"
        if os.path.isdir(wl_dir):
            print(f"  Wordlists:")
            for f in sorted(os.listdir(wl_dir)):
                path = os.path.join(wl_dir, f)
                if os.path.isfile(path):
                    try:
                        with open(path) as fh:
                            n = sum(1 for _ in fh)
                        print(f"    {f:30s} {n:>8d} lines")
                    except Exception:
                        pass
    except Exception:
        pass

    print()
    input("Enter...")


def menu_report_cleanup():
    """Удаление старых отчётов из reports/."""
    clear(); banner()
    print("  REPORT CLEANUP")
    print("  ==============")
    print()
    import os
    from pathlib import Path
    rd = Path("reports")
    if not rd.is_dir():
        print("  reports/ не найдена")
        input("Enter...")
        return
    files = sorted(rd.glob("*"), key=lambda f: f.stat().st_mtime)
    if not files:
        print("  reports/ пуста")
        input("Enter...")
        return
    print(f"  Всего файлов: {len(files)}")
    total_size = sum(f.stat().st_size for f in files if f.is_file())
    print(f"  Размер: {total_size / 1024 / 1024:.1f} MB")
    print()
    print("  Действия:")
    print("    a — удалить ВСЕ отчёты")
    print("    o — удалить старше 7 дней")
    print("    x — удалить конкретный по паттерну")
    print("    Enter — назад")
    c = input("  > ").strip().lower()

    import time
    if c == "a":
        confirm = input(f"  Удалить {len(files)} файлов? [y/N]: ").lower()
        if confirm == "y":
            for f in files:
                if f.is_file():
                    f.unlink()
            print(f"  Удалено: {len(files)}")
    elif c == "o":
        cutoff = time.time() - 7 * 86400
        old = [f for f in files if f.stat().st_mtime < cutoff]
        confirm = input(f"  Удалить {len(old)} файлов старше 7 дней? [y/N]: ").lower()
        if confirm == "y":
            for f in old:
                if f.is_file():
                    f.unlink()
            print(f"  Удалено: {len(old)}")
    elif c == "x":
        pat = input("  Паттерн (например 'testfire'): ").strip()
        if pat:
            matched = [f for f in files if pat in f.name]
            if matched:
                print(f"  Найдено: {len(matched)}")
                for f in matched[:10]:
                    print(f"    {f.name}")
                confirm = input("  Удалить? [y/N]: ").lower()
                if confirm == "y":
                    for f in matched:
                        if f.is_file():
                            f.unlink()
                    print(f"  Удалено: {len(matched)}")
    input("Enter...")


def menu_live_tests():
    """Live tests — test_all.py на demo.testfire.net."""
    clear(); banner()
    print("  LIVE TESTS — test_all.py")
    print("  =======================")
    print()
    print("  Прогон всех модулей на demo.testfire.net (IBM полигон)")
    print("  Может занять 5-15 минут")
    print()
    c = input("  Запустить? [y/N]: ").strip().lower()
    if c == "y":
        os.system("python test_all.py 2>&1 | tail -60")
    input("\nEnter...")



def main():
    try:
        menu_main()
    except KeyboardInterrupt:
        print("\n[выход]")


if __name__ == "__main__":
    main()

