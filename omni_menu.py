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
        print("  1. Одна атака (выбрать модуль)")
        print("  2. Цепочка (chain)")
        print("  3. Список всех модулей")
        print("  4. Список цепочек")
        print()
        print("  ИНСТРУМЕНТЫ:")
        print("  5. Аудит защиты (security_audit)")
        print("  6. CIS Compliance check")
        print("  7. CVE-скан (по fingerprint)")
        print("  8. Template scan (Nuclei-шаблоны)")
        print("  9. Payload lab (лаборатория)")
        print(" 10. Authenticated scan (с кредами)")
        print(" 11. Agent (автономное планирование)")
        print(" 12. Chameleon (детект WAF/honeypot)")
        print(" 13. Swarm (50 идентичностей)")
        print(" 14. Defense analysis (что видит SOC)")
        print()
        print("  СЕТЬ:")
        print(" 15. Прокси: обновить список")
        print(" 16. Прокси: показать рабочие")
        print(" 17. Tor: проверить")
        print(" 18. Proxy server (Burp-lite)")
        print(" 19. Templates: скачать все (Nuclei)")
        print(" 20. Wordlists: скачать SecLists")
        print()
        print("  ОТЧЁТЫ И АНАЛИЗ:")
        print(" 21. SARIF report (GitHub Security tab)")
        print(" 22. Diff сканов (что изменилось)")
        print(" 23. Webhook notify (Slack/Discord/Telegram)")
        print(" 24. PDF report (последний скан)")
        print()
        print("  РАСШИРЕННОЕ:")
        print(" 25. Template scan v2 (raw/dsl support)")
        print(" 26. Wordlists: показать доступные")
        print(" 27. Wordlists: скачать конкретный список")
        print(" 28. Verification stats (фильтр ложных сработок)")
        print()
        print("  0. Выход")
        print()
        c = ask("Выбор [0-28]: ")

        actions = {
            "1":  menu_run_module,
            "2":  menu_chain,
            "3":  menu_list,
            "4":  menu_chains_list,
            "5":  menu_audit,
            "6":  menu_compliance,
            "7":  menu_cve_scan,
            "8":  menu_template_scan,
            "9":  menu_payload_lab,
            "10": menu_auth_scan,
            "11": menu_agent,
            "12": menu_chameleon,
            "13": menu_swarm,
            "14": menu_defense,
            "15": menu_proxy_update,
            "16": menu_proxy_show,
            "17": menu_tor,
            "18": menu_proxy_server,
            "19": menu_download_templates,
            "20": menu_download_wordlists,
            "21": menu_sarif,
            "22": menu_diff,
            "23": menu_webhook,
            "24": menu_pdf_last,
            "25": menu_template_scan_v2,
            "26": menu_wordlists_show,
            "27": menu_wordlist_download,
            "28": menu_verify_stats,
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


def main():
    try:
        menu_main()
    except KeyboardInterrupt:
        print("\n[выход]")


if __name__ == "__main__":
    main()

