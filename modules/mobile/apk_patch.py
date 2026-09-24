"""apk_patch — explain apk decompile/recompile/patch workflow (apktool + zipalign + apksigner)"""
from pathlib import Path

STEPS = [
    ("decompile", "apktool d target.apk -o target_dir"),
    ("edit", "edit smali in target_dir/smali*/; edit AndroidManifest.xml; edit res/"),
    ("recompile", "apktool b target_dir -o target_patched.apk"),
    ("zipalign",  "zipalign -p 4 target_patched.apk target_aligned.apk"),
    ("sign",      "apksigner sign --ks release.jks --out target_signed.apk target_aligned.apk"),
    ("verify",    "apksigner verify --verbose target_signed.apk"),
]

class ApkPatch:
    def run(self, session, logger):
        print("[apk_patch] workflow (apktool required in PATH):")
        lines = ["# APK patch workflow", ""]
        for step, cmd in STEPS:
            print(f"  [{step}] {cmd}")
            lines.append(f"## {step}\n  {cmd}\n")
            logger.info("apk_patch_step", step=step)
        out = Path("reports") / "apk_patch_workflow.txt"
        out.parent.mkdir(exist_ok=True)
        out.write_text("\n".join(lines))
        return {"steps": STEPS}
