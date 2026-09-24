"""cms_detect — identify CMS/framework (wordpress, drupal, joomla, modx, opencart, bitrix)"""
import re
from core.http import HttpClient

SIGS = {
    "WordPress":  [r"/wp-content/", r"/wp-includes/", r"wp-json", r'name="generator" content="WordPress'],
    "Drupal":     [r"sites/default/files", r"Drupal\.settings", r"drupal\.js", r'name="Generator" content="Drupal'],
    "Joomla":     [r"/components/com_", r"/modules/mod_", r"joomla", r'name="generator" content="Joomla'],
    "Magento":    [r"/skin/frontend/", r"/js/mage/", r"Mage\.Cookies", r"magento"],
    "OpenCart":   [r"catalog/view/theme", r"index.php\?route=", r"opencart"],
    "Bitrix":     [r"/bitrix/", r"BX\.", r"bitrix"],
    "Modx":       [r"/manager/templates/", r"modx", r"MODX"],
    "TYPO3":      [r"typo3temp/", r"typo3conf/", r"TYPO3"],
    "PrestaShop": [r"/themes/.*prestashop", r"prestashop"],
    "Shopify":    [r"cdn\.shopify\.com", r"shopify"],
    "Ghost":      [r"ghost-url", r"ghost\.org"],
    "Confluence": [r"confluence", r"Atlassian Confluence"],
    "Jira":       [r"jira", r"Atlassian JIRA"],
    "MediaWiki":  [r"mediawiki", r"/wiki/"],
    "Django":     [r"csrfmiddlewaretoken", r"django"],
    "Laravel":    [r"laravel_session", r"XSRF-TOKEN"],
    "Rails":      [r"rails-ujs", r"actionpack", r"_rails"],
}

VERSION_RES = {
    "WordPress":  re.compile(r'content="WordPress\s+([\d.]+)"', re.I),
    "Drupal":     re.compile(r'Drupal\s+([\d.]+)', re.I),
    "Joomla":     re.compile(r'Joomla!\s+([\d.]+)', re.I),
}

class CmsDetect:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        r = http.get(session.target)
        if not r: return {}
        body = r.text
        headers = str(r.headers)
        found = []
        for cms, patterns in SIGS.items():
            for p in patterns:
                if re.search(p, body, re.I) or re.search(p, headers, re.I):
                    found.append(cms)
                    print(f"  [+] {cms}")
                    logger.finding("cms","info",cms)
                    # version
                    vr = VERSION_RES.get(cms)
                    if vr:
                        m = vr.search(body)
                        if m:
                            print(f"      version: {m.group(1)}")
                            logger.finding("cms_version","info",f"{cms} {m.group(1)}")
                    break
        # extra checks
        for probe in ["/wp-login.php","/administrator/","/user/login","/admin/login"]:
            r2 = http.get(session.target.rstrip("/") + probe)
            if r2 and r2.status_code == 200:
                print(f"  [+] admin panel: {probe}")
                logger.finding("cms_admin","low",probe)
        return {"cms": found}
