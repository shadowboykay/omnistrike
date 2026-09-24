# core/flow_engine.py — Nuclei v3 flow-control engine
import re, time
from core.template_engine import match_template


def evaluate_condition(cond, context):
    """
    Evaluate a flow condition like: contains(body, "foo")
    context: dict of variables from previous steps
    """
    cond = cond.strip()
    if not cond:
        return True

    # contains(variable, "string")
    m = re.match(r'contains\((\w+),\s*"([^"]+)"\)', cond)
    if m:
        var = context.get(m.group(1), "")
        return m.group(2) in str(var)

    # !contains(...)
    if cond.startswith("!"):
        return not evaluate_condition(cond[1:], context)

    # status_code == 200
    m = re.match(r'(\w+)\s*==\s*(\d+)', cond)
    if m:
        return context.get(m.group(1)) == int(m.group(2))

    # true / false
    if cond.lower() == "true":
        return True
    if cond.lower() == "false":
        return False

    return False


def run_flow(flow_steps, http, target, logger=None, context=None):
    """
    Execute Nuclei v3 flow steps sequentially.
    flow_steps: list of steps from 'flow:' block
    """
    context = context or {}
    findings = []

    for step in flow_steps:
        step_type = step.get("type", "http")
        name = step.get("name", "step")

        if step_type == "http":
            # run single HTTP request
            req = step.get("request", step)
            try:
                f = match_template({"http": [req], "info": step.get("info", {})},
                                   http, target, logger)
                if f:
                    context[f"step_{name}_matched"] = True
                    context[f"step_{name}_body"] = "matched"
                    findings.extend(f)
                else:
                    context[f"step_{name}_matched"] = False
                    context[f"step_{name}_body"] = ""
            except Exception as e:
                if logger:
                    logger.warn("flow_step_fail", name=name, error=str(e))

        elif step_type == "if":
            cond = step.get("condition", "")
            if evaluate_condition(cond, context):
                sub_findings = run_flow(step.get("steps", []), http, target, logger, context)
                findings.extend(sub_findings)

        elif step_type == "for":
            iterable = step.get("iterable", [])
            for item in iterable:
                context["item"] = item
                sub_findings = run_flow(step.get("steps", []), http, target, logger, context)
                findings.extend(sub_findings)

        elif step_type == "set":
            for k, v in step.get("values", {}).items():
                context[k] = v

        elif step_type == "sleep":
            duration = step.get("duration", 1)
            time.sleep(duration)

    return findings


def parse_flow(template):
    """Parse flow block from a template if present."""
    flow = template.get("flow")
    if not flow:
        return None
    if isinstance(flow, str):
        # flow as string — basic parse
        return [{"type": "http", "raw": flow}]
    if isinstance(flow, list):
        return flow
    return None
