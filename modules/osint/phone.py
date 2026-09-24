"""phone — phone number OSINT: format, carrier hint, region"""
import re
from core.http import HttpClient

class Phone:
    def run(self, session, logger):
        num = re.sub(r"[^\d+]", "", session.target)
        print(f"[phone] {num}")
        # basic parse
        if num.startswith("+"):
            country_code = num[1:4] if num[1:4] in ["790","791","792","793","794","795","796","797","798","799"] else num[1:3]
        else:
            country_code = None

        # region hints
        regions = {"+7":"RU/KZ","+1":"US/CA","+44":"UK","+49":"DE","+33":"FR","+86":"CN","+81":"JP","+65":"SG"}
        region = None
        for cc, r in regions.items():
            if num.startswith(cc): region = r; break
        print(f"  country_code={country_code} region={region}")
        logger.finding("phone","info",f"{num} region={region}")
        return {"number": num, "region": region, "country_code": country_code}
