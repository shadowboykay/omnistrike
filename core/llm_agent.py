# core/llm_agent.py — LLM-powered agent using Ollama (local, free)
"""
LLM-агент: принимает задачу → планирует шаги → запускает модули → анализирует.
Требует Ollama локально: https://ollama.ai/
  ollama pull llama3.2
  ollama serve
"""
import json
import re
import subprocess
import os
from pathlib import Path

ROOT = Path(__file__).parent.parent

SYSTEM_PROMPT = """Ты — пентест-ассистент в OmniStrike. Твоя задача: понять цель пользователя и выбрать правильную последовательность модулей.

Доступные категории модулей:
- recon: subdomain_brute, dns, waf_detect, tech_fingerprint, crt_sh, sitemap, robots, api_hunter, s3_bucket
- web: cors, csp, cookie, xss, sqli, lfi, ssrf, ssti, xxe, jwt, api_leak, backup, cms_detect, wpscan_lite, swagger, template_scan
- bypass: 403_bypass, waf_evasion, rate_limit
- exploit: cve_match, default_creds, subdomain_takeover, jwt_forge
- evasion: swarm_mode_v3, chameleon_v2, decoy_traffic

Для любой задачи верни JSON строго:
{"steps":[{"cat":"recon","mod":"waf_detect"},{"cat":"web","mod":"cors"}]}

Не добавляй объяснений. Только JSON. Максимум 10 шагов.

Правила:
- Начинай с recon/waf_detect для любой цели
- Если target с параметрами (?id=) — добавь web/sqli, web/xss
- Если нужен быстрый скан — recon/waf_detect, web/cors, web/cookie, web/api_leak
- Если задача "critical only" — web/backup, web/api_leak, web/jwt, web/sqli, web/lfi
"""


def ollama_chat(prompt, model=None):
    """Call Ollama API."""
    model = model or os.environ.get("OMNI_LLM_MODEL", "llama3.2")
    try:
        import requests
        url = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434/api/chat")
        r = requests.post(url, json={
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {"temperature": 0.2},
        }, timeout=120)
        if r.status_code == 200:
            return r.json().get("message", {}).get("content", "")
    except Exception as e:
        return f"LLM_ERROR: {e}"
    return None


def extract_plan(text):
    """Extract JSON plan from LLM response."""
    if not text:
        return None
    # find first {...} with "steps"
    m = re.search(r'\{[^{}]*"steps"[^{}]*\[.*?\][^{}]*\}', text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


class LLMAgent:
    def __init__(self, session, logger, loader=None):
        self.session = session
        self.logger = logger
        if loader is None:
            from core.loader import ModuleLoader
            loader = ModuleLoader()
        self.loader = loader
        self.executed = []

    def ask_llm_for_plan(self, task):
        """Ask LLM to build plan."""
        prompt = f"Цель: {self.session.target}\nЗадача: {task}\n\nПострой план из модулей."
        print(f"[llm] asking {os.environ.get('OMNI_LLM_MODEL', 'llama3.2')}...")
        resp = ollama_chat(prompt)
        if not resp:
            return None
        if resp.startswith("LLM_ERROR"):
            print(f"[llm] {resp}")
            return None
        print(f"[llm] response:\n{resp[:500]}\n")
        return extract_plan(resp)

    def fallback_plan(self, task):
        """Rule-based fallback if LLM unavailable."""
        plans = {
            "recon": [("recon","waf_detect"), ("recon","tech_fingerprint"),
                      ("recon","cms_detect")],
            "quick": [("recon","waf_detect"), ("web","cors"), ("web","cookie"),
                      ("web","api_leak")],
            "critical": [("recon","waf_detect"), ("web","backup"),
                         ("web","api_leak"), ("web","jwt"), ("web","sqli")],
        }
        return {"steps": [{"cat": c, "mod": m} for c, m in plans.get(task, plans["quick"])]}

    def run(self, task="quick"):
        print(f"[llm-agent] target: {self.session.target}")
        print(f"[llm-agent] task: {task}")
        print()

        plan = self.ask_llm_for_plan(task)
        if not plan:
            print("[llm] fallback to rule-based plan")
            plan = self.fallback_plan(task)

        steps = plan.get("steps", [])
        print(f"[llm-agent] plan: {len(steps)} steps")
        for i, s in enumerate(steps, 1):
            print(f"  {i}. {s.get('cat')}/{s.get('mod')}")
        print()

        for i, s in enumerate(steps, 1):
            cat = s.get("cat")
            mod = s.get("mod")
            print(f"[{i}/{len(steps)}] {cat}/{mod}")

            m = self.loader.load(cat, mod)
            if not m:
                print(f"  skip (not found)")
                continue

            try:
                m.run(self.session, self.logger)
                self.executed.append(f"{cat}/{mod}")
            except KeyboardInterrupt:
                raise
            except Exception as e:
                print(f"  error: {type(e).__name__}")

        print()
        print(f"[llm-agent] done. steps: {len(self.executed)}, "
              f"findings: {len(self.session.findings)}")
        return {"steps": self.executed, "findings": len(self.session.findings)}


def run_llm_agent(session, logger, task="quick"):
    return LLMAgent(session, logger).run(task)
