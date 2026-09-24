"""compliance_check — CIS Benchmark / PCI / HIPAA check"""
from core.compliance import load_benchmark, run_check
from core.http import HttpClient
from pathlib import Path


class ComplianceCheck:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        # find benchmark name from --extra benchmark=cis_web
        bench_name = None
        for x in session.extra:
            if x.startswith("benchmark="):
                bench_name = x.split("=", 1)[1]

        available = [p.stem for p in (Path(__file__).parent.parent.parent / "data" / "compliance").glob("*.yaml")]
        print(f"[compliance] available: {available}")
        print()

        if not bench_name:
            print("[compliance] укажи --extra 'benchmark=cis_web'")
            return {"available": available}

        bench = load_benchmark(bench_name)
        if not bench:
            print(f"[compliance] benchmark {bench_name} не найден")
            return {"error": "no benchmark"}

        print(f"[compliance] {bench['name']} v{bench['version']}")
        print(f"[compliance] checks: {len(bench['checks'])}")
        print()

        passed = 0
        failed = 0
        warnings = 0
        findings = []

        for check in bench["checks"]:
            ok, detail = run_check(check, http, target)
            sev = check.get("severity", "info")

            if ok is True:
                print(f"  + [{check['id']}] {check['title']}: PASS")
                passed += 1
            elif ok is False:
                print(f"  ! [{check['id']}] {check['title']}: FAIL — {detail}")
                failed += 1
                findings.append({"id": check["id"], "title": check["title"],
                                 "severity": sev, "detail": detail})
                logger.finding("compliance_fail", sev,
                               f"CIS {check['id']}: {check['title']}")
            else:
                print(f"  ? [{check['id']}] {check['title']}: SKIP — {detail}")
                warnings += 1

        total = passed + failed + warnings
        score = (passed / total * 100) if total else 0

        print()
        print(f"[compliance] score: {score:.1f}% ({passed}/{total} passed)")
        print(f"  passed: {passed}, failed: {failed}, warnings: {warnings}")

        return {"benchmark": bench["name"], "score": score,
                "passed": passed, "failed": failed,
                "findings": findings}
