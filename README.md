# OmniStrike v2

![status](https://img.shields.io/badge/status-active-brightgreen)
![python](https://img.shields.io/badge/python-3.11+-blue)
![modules](https://img.shields.io/badge/modules-178-orange)
![templates](https://img.shields.io/badge/templates-14060-purple)
![license](https://img.shields.io/badge/license-MIT-green)
![tests](https://img.shields.io/badge/tests-7%20passing-brightgreen)

**Modular pentest framework for Termux and Linux.**
195+ modules across 12 categories, 14060 Nuclei templates, KEV/ExploitDB/GHSA CVE cache, Burp-lite proxy, Flask web UI, SARIF/JUnit/PDF reports.

## Features

| Category | Count | Description |
|---|---|---|
| recon | 23 | subdomain (DoH), DNS, WAF, CMS, dorks, wayback, s3 |
| web | 57 | sqli, xss, lfi, ssti, ssrf, xxe, jwt, cors, saml, oauth |
| bypass | 8 | WAF evasion, 403, smuggling, cache poison |
| exploit | 23 | CVE chain, log4shell, shellshock, k8s chain |
| evasion | 30 | Googlebot, swarm (50 id), chameleon, decoy, JA3 |
| c2 | 5 | listener, agent, beacon DNS, malleable C2, stager |
| post | 7 | persistence, loot, privesc, lateral, defense |
| osint | 6 | email, username, phone, ip, domain, dox |
| mobile | 6 | APK, patch, dex, frida, traffic, iOS |
| cloud | 5 | s3, azure, gcp, cloudflare origin, k8s chain |
| ad | 6 | ldap, kerberoast, asreproast, smb, zerologon |
| dump | 7 | sqli_dump, lfi_dump, ssrf_dump, xxe_dump, rce_dump |

## Features

| Category | Count | Description |
|---|---|---|
| recon | 23 | subdomain (DoH), DNS, WAF, CMS, dorks, wayback, s3 |
| web | 57 | sqli, xss, lfi, ssti, ssrf, xxe, jwt, cors, saml, oauth |
| bypass | 8 | WAF evasion, 403, smuggling, cache poison |
| exploit | 23 | CVE chain, log4shell, shellshock, k8s chain |
| evasion | 30 | Googlebot, swarm (50 id), chameleon, decoy, JA3 |
| c2 | 5 | listener, agent, beacon DNS, malleable C2, stager |
| post | 7 | persistence, loot, privesc, lateral, defense |
| osint | 6 | email, username, phone, ip, domain, dox |
| mobile | 6 | APK, patch, dex, frida, traffic, iOS |
| cloud | 5 | s3, azure, gcp, cloudflare origin, k8s chain |
| ad | 6 | ldap, kerberoast, asreproast, smb, zerologon |
| dump | 7 | sqli_dump, lfi_dump, ssrf_dump, xxe_dump, rce_dump |

## Quick Start

```bash
git clone https://github.com/shadowboykay/omnistrike.git
cd omnistrike
pip install requests urllib3 flask
python -c "from core.template_full import download_full; download_full()"
python -c "from core.wordlist_mgr import download_all; download_all()"
python -c "from core.cve_db import update_all; update_all()"
```

## Usage

Menu (27 actions):
```bash
python omni_menu.py
```

CLI:
```bash
python omni.py list
python omni.py run recon subdomain_brute --target example.com
python omni.py run web sqli --target "http://target.com/?id=1"
python omni.py run web xss --target "http://target.com/?q=test"
python omni.py chain recon --target example.com
python omni.py chain full --target http://target.com/
```

## CI/CD Mode

```bash
python omni.py run recon waf_detect --target "http://target.com/" --ci
python omni.py run web sqli --target "http://target.com/?id=1" --junit
python omni.py run web sqli --target "http://target.com/?id=1" --sarif
python omni.py run recon waf_detect --target "http://target.com/" --pdf
```

## Proxy (Burp-lite)

```bash
python omni_proxy.py 8080
python omni_proxy.py 8080 --edit
```

## Web UI

```bash
python omni_web.py 5000
```

## Unique Features

**Chameleon** — WAF/honeypot/IDS detection via 4 levels.
```bash
python omni.py run evasion chameleon_v2 --target "http://target.com/"
```

**Swarm** — 50 identities parallel + auto-differential.
```bash
python omni.py run evasion swarm_mode_v3 --target "http://target.com/"
```

**Decoy traffic** — realistic sessions parallel to attack.
```bash
python omni.py run evasion decoy_traffic --target "http://target.com/"
```

**CVE chain** — detect → exploit → post-exploit.
```bash
python omni.py run exploit cve_match --target "http://target.com/" --extra chain=1
```

## Payload System

17 contexts, ~5900 payloads with auto-mutation and WAF detection:
- SQLi (667), XSS (9977), LFI (1082), SSTI (133), SSRF (102)

## Reports

JSON, MD, HTML, SARIF, JUnit XML

## Architecture

```
omni.py           CLI
omni_menu.py      interactive menu (27)
omni_proxy.py     Burp-lite HTTP proxy
omni_web.py       Flask web UI
core/             kernel (40+ files)
modules/          195 modules
payloads/         17 contexts
wordlists/        175k+ words
templates/        14060 Nuclei
```

## License

MIT


---

Автор не несёт ответственности за ваши действия.
