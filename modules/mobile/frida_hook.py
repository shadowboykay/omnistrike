"""frida_hook — generate frida hook templates for common android targets"""
from pathlib import Path

TEMPLATES = {
    "ssl_pinning_bypass": '''
Java.perform(function() {
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    TrustManager.checkClientTrusted.implementation = function() {};
    TrustManager.checkServerTrusted.implementation = function() {};
    var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
    HostnameVerifier.verify.implementation = function() { return true; };
});
''',
    "root_bypass": '''
Java.perform(function() {
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.isRooted.implementation = function() { return false; };
});
''',
    "log_all_crypto": '''
Java.perform(function() {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function(input) {
        console.log("doFinal input: " + bytesToHex(input));
        var out = this.doFinal(input);
        console.log("doFinal output: " + bytesToHex(out));
        return out;
    };
    function bytesToHex(b) {
        var s = ""; for (var i = 0; i < b.length; i++) s += ("0" + (b[i] & 0xFF).toString(16)).slice(-2);
        return s;
    }
});
''',
    "dump_strings": '''
Java.perform(function() {
    var String = Java.use("java.lang.String");
    String.$init.overload("[B").implementation = function(b) {
        var s = this.$init(b);
        console.log("[str] " + s);
        return s;
    };
});
''',
}

class FridaHook:
    def run(self, session, logger):
        out_dir = Path("payloads") / "frida"
        out_dir.mkdir(parents=True, exist_ok=True)
        for name, code in TEMPLATES.items():
            p = out_dir / f"{name}.js"
            p.write_text(code)
            print(f"  [+] {name} -> {p}")
            logger.info("frida_template", name=name, path=str(p))
        print(f"[frida_hook] {len(TEMPLATES)} templates in {out_dir}")
        return {"templates": list(TEMPLATES.keys()), "dir": str(out_dir)}
