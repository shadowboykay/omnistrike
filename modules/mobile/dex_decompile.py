"""dex_decompile — APK → DEX → decompile via jadx/dex2jar (checklist + extraction)"""
from pathlib import Path
import zipfile, subprocess

class DexDecompile:
    def run(self, session, logger):
        apk = Path(session.target)
        if not apk.is_file():
            print(f"[dex] not a file: {apk}"); return {}

        out_dir = Path("reports") / "dex" / apk.stem
        out_dir.mkdir(parents=True, exist_ok=True)

        # extract dex files
        try:
            with zipfile.ZipFile(apk) as z:
                dexes = [n for n in z.namelist() if n.endswith(".dex")]
                for d in dexes:
                    (out_dir / d).write_bytes(z.read(d))
                    print(f"  extracted {d} ({len(z.read(d))} bytes)")
        except Exception as e:
            print(f"  zip error: {e}")

        # try jadx if available
        for tool, cmd in [("jadx", f"jadx -d {out_dir}/jadx {apk}"),
                          ("d2j-dex2jar", f"d2j-dex2jar {apk} -o {out_dir}/{apk.stem}.jar"),
                          ("apktool", f"apktool d -f -o {out_dir}/apktool {apk}")]:
            try:
                subprocess.run(cmd, shell=True, timeout=120, capture_output=True)
                print(f"  [+] {tool}: done")
                logger.info("dex_decompile", tool=tool, out=str(out_dir))
            except FileNotFoundError:
                print(f"  [-] {tool}: not installed")
            except Exception as e:
                print(f"  [-] {tool}: {e}")

        print(f"[dex] output: {out_dir}")
        return {"out_dir": str(out_dir)}
