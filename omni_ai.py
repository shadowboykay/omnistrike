#!/usr/bin/env python3
# omni_ai.py — AI assistant for OmniStrike (Ollama or OpenAI-compatible)
import os, sys, subprocess, json
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))


SYSTEM_PROMPT = """Ты — AI-ассистент в пентест-фреймворке OmniStrike.
Твоя задача: понять запрос пользователя, выбрать правильный модуль/цепочку, запустить его.

Доступные категории: recon, web, bypass, exploit, evasion, c2, post, osint, mobile, cloud, ad, dump.
Доступные цепочки: recon, web, bypass, evasion, cloud, osint, dump, full, extended, auto, exploit.

Отвечай коротко. Если нужно запустить команду — верни JSON:
{"action": "run", "category": "web", "module": "sqli", "target": "URL"}
{"action": "chain", "chain": "recon", "target": "URL"}
{"action": "answer", "text": "..."}

Не запускай атаки по чужим целям без явного разрешения пользователя."""


def call_llm(prompt, model=None):
    """Call local Ollama or OpenAI-compatible endpoint."""
    provider = os.environ.get("OMNI_LLM_PROVIDER", "ollama")
    if provider == "ollama":
        url = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434/api/chat")
        model = model or os.environ.get("OMNI_MODEL", "llama3.2")
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
        }
        try:
            import requests
            r = requests.post(url, json=payload, timeout=120)
            if r.status_code == 200:
                return r.json().get("message", {}).get("content", "")
        except Exception as e:
            return f"LLM error: {e}"
    return "No LLM configured. Set OMNI_LLM_PROVIDER."


def run_omni(action):
    """Execute the action returned by LLM."""
    a = action.get("action")
    if a == "run":
        cmd = [sys.executable, str(ROOT / "omni.py"), "run",
               action["category"], action["module"],
               "--target", action["target"]]
        subprocess.run(cmd, cwd=ROOT)
    elif a == "chain":
        cmd = [sys.executable, str(ROOT / "omni.py"), "chain",
               action["chain"], "--target", action["target"]]
        subprocess.run(cmd, cwd=ROOT)
    elif a == "answer":
        print(action.get("text", ""))


def repl():
    print("OmniStrike AI — введи задачу (Ctrl+C для выхода)")
    print("пример: 'просканируй http://target.com на XSS'")
    print()
    while True:
        try:
            q = input("> ").strip()
            if not q:
                continue
            resp = call_llm(q)
            print(f"\n[AI]: {resp}\n")
            # try to parse JSON action
            import re
            m = re.search(r"\{[^}]+\}", resp, re.DOTALL)
            if m:
                try:
                    action = json.loads(m.group(0))
                    if action.get("action") in ("run", "chain"):
                        print(f"[executing]: {action}")
                        run_omni(action)
                except Exception:
                    pass
        except KeyboardInterrupt:
            print("\n[выход]")
            break


if __name__ == "__main__":
    repl()
