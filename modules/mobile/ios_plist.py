"""ios_plist — iOS .plist analysis (info.plist from IPA, entitlements)"""
from pathlib import Path
import plistlib, zipfile

class IosPlist:
    def run(self, session, logger):
        target = Path(session.target)
        if target.suffix.lower() == ".ipa":
            # extract Payload/*.app/Info.plist
            try:
                with zipfile.ZipFile(target) as z:
                    for n in z.namelist():
                        if n.endswith("Info.plist") and "Payload/" in n:
                            data = z.read(n)
                            try:
                                pl = plistlib.loads(data)
                                print(f"[ios_plist] {n}")
                                for k in ["CFBundleIdentifier","CFBundleVersion",
                                          "CFBundleShortVersionString","NSAppTransportSecurity",
                                          "UIBackgroundModes","LSApplicationQueriesSchemes"]:
                                    if k in pl:
                                        print(f"  {k}: {pl[k]}")
                                        logger.finding("ios_plist","info",f"{k}: {str(pl[k])[:100]}")
                                return {"plist": {k:str(v)[:200] for k,v in pl.items()}}
                            except Exception as e:
                                print(f"  parse error: {e}")
            except Exception as e:
                print(f"[ios_plist] zip error: {e}")
                return {}
        elif target.suffix.lower() == ".plist":
            try:
                with open(target, "rb") as f:
                    pl = plistlib.load(f)
                for k, v in pl.items():
                    print(f"  {k}: {str(v)[:100]}")
                return {"plist": {k:str(v)[:200] for k,v in pl.items()}}
            except Exception as e:
                print(f"[ios_plist] error: {e}")
        else:
            print(f"[ios_plist] expected .ipa or .plist, got: {target.suffix}")
        return {}
