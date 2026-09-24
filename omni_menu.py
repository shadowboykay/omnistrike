#!/usr/bin/env python3
# omni_menu.py — interactive menu for OmniStrike v2
import sys, os, subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from core.loader import ModuleLoader
from core.session import Session
from core.logger import Logger
from core.report import Reporter
from core.spread import attach as spread_attach
from core.pipeline import CHAINS, run_chain

CATEGORIES = ["recon","web","bypass","exploit","evasion","c2","post","osint",
              "mobile","cloud","ad","dump"]


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


def menu_main():
    while True:
        clear()
        banner()
        print("  1. Одна атака (выбрать модуль)")
        print("  2. Цепочка (chain: recon/web/bypass/full)")
        print("  3. Список всех модулей")
        print("  4. Список цепочек")
        print("  5. Аудит защиты сайта (security_audit)")
        print("  6. Выход")
        print()
        c = ask("Выбор [1-6]: ")
        if c == "1": menu_run_module()
        elif c == "2": menu_chain()
        elif c == "3": menu_list()
        elif c == "4": menu_chains_list()
        elif c == "5": menu_audit()
        elif c == "6": break
        else: input("Неверно. Enter для продолжения")


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
        input("Нет модулей в категории. Enter...")
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

    # extra args
    extra = []
    if cat == "web" and "post" in mod:
        post = ask("POST данные (uid=1&passw=1, Enter чтобы пропустить): ")
        if post: extra.append(f"post={post}")
    proxy = ask("Proxy (socks5://... или Enter): ")
    spread = ask("Включить автораспространение? [y/N]: ").lower() == "y"
    pause = ask("Пауза после каждой находки? [y/N]: ").lower() == "y"

    # run
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
        print(f"[!] ошибка: {type(e).__name__}: {e}")
        return

    reporter.write(result)

    if spread_engine:
        print("\n[spread] summary:")
        for k, v in spread_engine.summary().items():
            print(f"  {k}: {v}")

    input("\nEnter для возврата в меню...")


def menu_chain():
    clear(); banner()
    print("Цепочки:")
    print("  1. recon   (23 модуля разведки)")
    print("  2. web     (53 модуля web)")
    print("  3. bypass  (8 модулей обхода)")
    print("  4. evasion (23 модуля маскировки)")
    print("  5. cloud   (4 модуля облака)")
    print("  6. osint   (6 модулей OSINT)")
    print("  7. dump    (7 модулей выгрузки)")
    print("  8. full    (recon+web+bypass)")
    print("  9. extended (всё вместе)")
    print(" 10. auto    (recon → scan → dump → reuse)")
    print(" 11. Назад")
    print()
    c = ask("Выбор [1-11]: ")
    chains = {1:"recon",2:"web",3:"bypass",4:"evasion",5:"cloud",6:"osint",
              7:"dump",8:"full",9:"extended",10:"auto"}
    if c == "11": return
    try:
        chain_name = chains[int(c)]
    except (ValueError, KeyError):
        return

    target = ask("Target: ")
    if not target: return
    proxy = ask("Proxy (Enter для пропуска): ")
    spread = ask("Автораспространение? [y/N]: ").lower() == "y"

    clear(); banner()
    print(f"Цепочка: {chain_name} -> {target}")
    print("=" * 60)

    try:
        session = run_chain(chain_name, target, proxy=proxy or None)
        print(f"\n[done] findings: {len(session.findings)}")
    except KeyboardInterrupt:
        print("\n[!] прервано")
    except Exception as e:
        print(f"[!] {type(e).__name__}: {e}")

    input("\nEnter для возврата...")


def menu_list():
    clear(); banner()
    loader = ModuleLoader()
    for cat in CATEGORIES:
        mods = loader.list_category(cat)
        print(f"\n=== {cat} ({len(mods)}) ===")
        for name, desc in sorted(mods.items()):
            print(f"  {name:28s} {desc[:60]}")
    input("\nEnter для возврата...")


def menu_chains_list():
    clear(); banner()
    for name, steps in CHAINS.items():
        if steps is None:
            print(f"  {name}: auto (special)")
        else:
            print(f"  {name}: {len(steps)} steps")
    input("\nEnter для возврата...")


def menu_audit():
    clear(); banner()
    target = ask("Target для аудита: ")
    if not target: return
    os.system(f"python omni.py run recon security_audit --target '{target}'")
    input("\nEnter для возврата...")


def main():
    try:
        menu_main()
    except KeyboardInterrupt:
        print("\n[выход]")


if __name__ == "__main__":
    main()
