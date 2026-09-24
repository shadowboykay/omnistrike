# omni.py — OmniStrike v2 CLI entry point
import argparse, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from core.loader import ModuleLoader
from core.session import Session
from core.logger import Logger
from core.report import Reporter
from core.pipeline import run_chain, CHAINS

CATEGORIES = ["recon","web","bypass","exploit","evasion","c2","post","osint","mobile","cloud","ad","dump"]


def cmd_list(args):
    loader = ModuleLoader()
    cats = [args.category] if args.category else CATEGORIES
    for cat in cats:
        mods = loader.list_category(cat)
        if mods:
            print(f"\n=== {cat} ({len(mods)}) ===")
            for name, desc in sorted(mods.items()):
                print(f"  {name:24s} {desc}")


def cmd_run(args):
    loader = ModuleLoader()
    module = loader.load(args.category, args.module)
    if not module:
        print(f"[!] module '{args.category}/{args.module}' not found"); sys.exit(1)
    session = Session(
        target=args.target, proxy=args.proxy, timeout=args.timeout,
        user_agent=args.ua, threads=args.threads, output=args.output,
        extra=args.extra,
    )
    logger = Logger(session)
    reporter = Reporter(session, logger)
    print(f"[omni] {args.category}/{args.module} -> {args.target}")
    logger.info("start", category=args.category, module=args.module, target=args.target)
    try:
        result = module.run(session, logger)
    except KeyboardInterrupt:
        print("\n[!] interrupted"); logger.warn("interrupted"); sys.exit(130)
    except Exception as e:
        logger.error("crash", error=str(e)); print(f"[!] {type(e).__name__}: {e}"); sys.exit(2)
    reporter.write(result)


def cmd_chain(args):
    run_chain(args.name, args.target, proxy=args.proxy,
              timeout=args.timeout, threads=args.threads)


def main():
    p = argparse.ArgumentParser(prog="omni", description="OmniStrike v2")
    sub = p.add_subparsers(dest="cmd")

    pl = sub.add_parser("list")
    pl.add_argument("category", nargs="?", default=None, choices=CATEGORIES)

    pr = sub.add_parser("run")
    pr.add_argument("category", choices=CATEGORIES)
    pr.add_argument("module")
    pr.add_argument("--target","-t", required=True)
    pr.add_argument("--proxy","-p", default=None)
    pr.add_argument("--timeout", type=int, default=10)
    pr.add_argument("--ua", default=None)
    pr.add_argument("--threads", type=int, default=10)
    pr.add_argument("--output","-o", default=None)
    pr.add_argument("--extra","-x", action="append", default=[])

    pc = sub.add_parser("chain")
    pc.add_argument("name", choices=list(CHAINS.keys()))
    pc.add_argument("--target","-t", required=True)
    pc.add_argument("--proxy","-p", default=None)
    pc.add_argument("--timeout", type=int, default=10)
    pc.add_argument("--threads", type=int, default=10)

    args = p.parse_args()
    if args.cmd == "list": cmd_list(args)
    elif args.cmd == "run": cmd_run(args)
    elif args.cmd == "chain": cmd_chain(args)
    else: p.print_help()


if __name__ == "__main__":
    main()
