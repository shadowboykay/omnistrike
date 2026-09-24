# core/agent_planner.py — autonomous planner (rule-based, no LLM)
from core.loader import ModuleLoader


class AgentPlanner:
    PLANS = {
        "recon": [("recon","waf_detect"), ("recon","tech_fingerprint"),
                  ("web","cms_detect"),
                   ("recon","robots")],
        "web_scan": [("recon","waf_detect"), ("web","cors"), ("web","csp"),
                     ("web","cookie"), ("web","swagger"), ("web","api_leak"),
                     ("web","jwt"), ("web","xss"), ("web","sqli"), ("web","lfi")],
        "critical_only": [("recon","waf_detect"), ("web","backup"),
                          ("web","api_leak"), ("web","jwt"), ("web","sqli"),
                          ("web","lfi"), ("web","ssrf")],
    }

    REACTIVE = {
        "sqli": [("dump","sqli_dump")],
        "lfi":  [("dump","lfi_dump")],
        "ssrf": [("dump","ssrf_dump")],
        "waf":  [("bypass","waf_evasion")],
    }

    def __init__(self, session, logger, loader=None):
        self.session = session
        self.logger = logger
        self.loader = loader or ModuleLoader()
        self.executed = []

    def plan(self, task):
        return list(self.PLANS.get(task, self.PLANS["web_scan"]))

    def react(self, plan):
        added = []
        kinds = {f.get("kind", "") for f in self.session.findings}
        for trigger, steps in self.REACTIVE.items():
            if any(trigger in k for k in kinds):
                for step in steps:
                    if step not in plan:
                        plan.append(step)
                        added.append(step)
        return added

    def run(self, task="web_scan", max_steps=20):
        print(f"[agent] target: {self.session.target}")
        print(f"[agent] task: {task}")
        plan = self.plan(task)
        print(f"[agent] plan: {len(plan)} steps")
        print()

        step = 0
        while plan and step < max_steps:
            cat, mod = plan.pop(0)
            step += 1
            print(f"[{step}] {cat}/{mod}")

            m = self.loader.load(cat, mod)
            if not m:
                print("  skip (not found)")
                continue

            try:
                m.run(self.session, self.logger)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                print(f"  error: {type(e).__name__}")
                continue

            self.executed.append(f"{cat}/{mod}")
            added = self.react(plan)
            if added:
                print(f"  [agent] +plan: {added}")

            criticals = [f for f in self.session.findings if f.get("severity") == "critical"]
            if len(criticals) >= 5:
                print(f"\n[agent] early stop: {len(criticals)} criticals")
                break

        print(f"\n[agent] done. steps: {len(self.executed)}, findings: {len(self.session.findings)}")
        return {"steps": self.executed, "findings": len(self.session.findings)}


def run_agent(session, logger, task="web_scan"):
    return AgentPlanner(session, logger).run(task)
