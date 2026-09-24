#!/usr/bin/env python3
"""run_stand.py — прогон OmniStrike на учебном стенде, с полным отчётом"""
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from core.loader import ModuleLoader
from core.session import Session
from core.logger import Logger
from core.report import Reporter


STANDS = {
    "vulnweb": {
        "base": "http://testphp.vulnweb.com",
        "targets": {
            "sqli":   "/artists.php?artist=1",
            "xss":    "/search.php?test=query",
            "lfi":    "/showimage.php?file=1",
            "all":    "/artists.php?artist=1",
        },
    },
    "dvwa": {
        "base": "http://localhost:8080",
        "targets": {
            "sqli":   "/vulnerabilities/sqli/?id=1&Submit=Submit",
            "xss":    "/vulnerabilities/xss_r/?name=test",
            "lfi":    "/vulnerabilities/fi/?page=include.php",
            "all":    "/vulnerabilities/sqli/?id=1",
        },
    },
}


MODULES = {
    "sqli":   [("web","sqli"),("dump","sqli_dump")],
    "xss":    [("web","xss"),("web","xss_dom")],
    "lfi":    [("web","lfi"),("dump","lfi_dump")],
    "ssrf":   [("web","ssrf"),("dump","ssrf_dump")],
    "basic":  [("recon","waf_detect"),("recon","tech_fingerprint"),("recon","cms_detect"),
               ("web","cors"),("web","csp"),("web","cookie"),("web","backup"),("web","api_leak")],
    "all":    [("recon","waf_detect"),("recon","tech_fingerprint"),("recon","cms_detect"),
               ("web","cors"),("web","csp"),("web","cookie"),("web","backup"),("web","api_leak"),
               ("web","jwt"),("web","swagger"),("web","xss"),("web","sqli"),("web","lfi"),
               ("dump","sqli_dump"),("dump","lfi_dump")],
}


def main():
    if len(sys.argv) < 3:
        print("usage: python run_stand.py <stand> <mode>")
        print("  stand: vulnweb | dvwa")
        print("  mode:  sqli | xss | lfi | ssrf | basic | all")
        sys.exit(1)

    stand = sys.argv[1]
    mode = sys.argv[2]
    if stand not in STANDS:
        print(f"unknown stand: {stand}"); sys.exit(1)
    if mode not in MODULES:
        print(f"unknown mode: {mode}"); sys.exit(1)

    cfg = STANDS[stand]
    target = cfg["base"] + cfg["targets"].get(mode, cfg["targets"]["all"])
    print(f"[stand] {stand} mode={mode}")
    print(f"[stand] target: {target}")
    print(f"[stand] modules: {len(MODULES[mode])}")
    print(f"[stand] ---")

    session = Session(target=target, timeout=8, threads=10)
    logger = Logger(session, log_dir="logs")
    loader = ModuleLoader()

    for i, (cat, name) in enumerate(MODULES[mode], 1):
        print(f"\n[{i}/{len(MODULES[mode])}] {cat}/{name}")
        try:
            m = loader.load(cat, name)
            if not m:
                print(f"  skip (not found)")
                continue
            t0 = time.time()
            m.run(session, logger)
            print(f"  ({time.time()-t0:.1f}s)")
        except KeyboardInterrupt:
            print("\n[!] interrupted")
            break
        except Exception as e:
            print(f"  error: {type(e).__name__}: {e}")

    reporter = Reporter(session, logger)
    reporter.write({"stand": stand, "mode": mode})


if __name__ == "__main__":
    main()
