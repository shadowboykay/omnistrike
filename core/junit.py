# core/junit.py — JUnit XML for CI
from pathlib import Path
from datetime import datetime
import xml.etree.ElementTree as ET


def generate(session, out_path=None, suite_name="omnistrike"):
    findings = session.findings
    target = session.target
    ts = ET.Element("testsuite", {
        "name": suite_name,
        "tests": str(max(len(findings), 1)),
        "failures": str(sum(1 for f in findings if f.get("severity") in ("critical", "high"))),
        "errors": "0", "time": "0",
        "timestamp": datetime.now().isoformat(),
    })
    props = ET.SubElement(ts, "properties")
    ET.SubElement(props, "property", {"name": "target", "value": target})
    if not findings:
        ET.SubElement(ts, "testcase", {"classname": suite_name, "name": "scan_clean", "time": "0"})
    else:
        for i, f in enumerate(findings):
            sev = f.get("severity", "info")
            kind = f.get("kind", "unknown")
            detail = f.get("detail", "")
            tc = ET.SubElement(ts, "testcase", {"classname": suite_name, "name": f"{kind}_{i}", "time": "0"})
            if sev in ("critical", "high"):
                fail = ET.SubElement(tc, "failure", {"type": sev, "message": detail[:200]})
                fail.text = detail
            else:
                ET.SubElement(tc, "system-out").text = f"[{sev}] {detail}"
    tree = ET.ElementTree(ts)
    ET.indent(tree, space="  ")
    if not out_path:
        t = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = "".join(c if c.isalnum() else "_" for c in target)[:60]
        out_path = Path("reports") / f"{t}_{safe}.junit.xml"
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    tree.write(out_path, encoding="utf-8", xml_declaration=True)
    print(f"[junit] -> {out_path}")
    return str(out_path)
