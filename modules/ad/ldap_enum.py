"""ldap_enum — anonymous LDAP enumeration (users, groups, computers)"""
from core.http import HttpClient

class LdapEnum:
    def run(self, session, logger):
        host = session.target.replace("https://","").replace("http://","").split("/")[0]
        if ":" in host: host = host.split(":")[0]
        http = HttpClient(session, logger)
        print(f"[ldap_enum] {host}")

        # uses ldapsearch if available
        import subprocess
        base_dns = host.split(".")
        base = ",".join(f"dc={p}" for p in base_dns)
        print(f"  base DN: {base}")

        cmds = {
            "root_dse": f"ldapsearch -x -H ldap://{host} -s base",
            "naming_contexts": f"ldapsearch -x -H ldap://{host} -s base namingContexts",
            "users": f"ldapsearch -x -H ldap://{host} -b '{base}' '(objectClass=user)'",
            "groups": f"ldapsearch -x -H ldap://{host} -b '{base}' '(objectClass=group)'",
        }
        results = {}
        for name, cmd in cmds.items():
            try:
                out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                text = out.stdout
                count = text.count("dn:")
                results[name] = count
                print(f"  {name}: {count} entries")
                if count > 0:
                    logger.finding("ldap_anon","high",f"{name}: {count} entries from {host}")
            except FileNotFoundError:
                print("  ldapsearch not found — pkg install openldap")
                return {}
            except Exception as e:
                print(f"  {name}: error {e}")

        print(f"[ldap_enum] done")
        return results
