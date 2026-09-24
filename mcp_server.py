#!/usr/bin/env python3
# mcp_server.py — MCP server for OmniStrike (Claude, Cursor, любой MCP-клиент)
"""
Minimal MCP-like server exposing OmniStrike as tools.
Protocol: JSON-RPC over stdio.
Works with any MCP client that supports stdio.
"""
import sys, json, subprocess
from pathlib import Path

ROOT = Path(__file__).parent


def list_tools():
    return {
        "tools": [
            {"name": "omni_list", "description": "List all OmniStrike modules"},
            {"name": "omni_run", "description": "Run a single module",
             "inputSchema": {"type": "object", "properties": {
                 "category": {"type": "string"},
                 "module": {"type": "string"},
                 "target": {"type": "string"},
                 "extra": {"type": "array", "items": {"type": "string"}},
             }, "required": ["category", "module", "target"]}},
            {"name": "omni_chain", "description": "Run a chain",
             "inputSchema": {"type": "object", "properties": {
                 "chain": {"type": "string"},
                 "target": {"type": "string"},
             }, "required": ["chain", "target"]}},
            {"name": "omni_chameleon", "description": "Detect target type (WAF/honeypot/normal)"},
            {"name": "omni_cve_lookup", "description": "Look up CVE info from local cache",
             "inputSchema": {"type": "object", "properties": {
                 "cve_id": {"type": "string"},
             }, "required": ["cve_id"]}},
        ]
    }


def call_tool(name, args):
    if name == "omni_list":
        r = subprocess.run([sys.executable, str(ROOT / "omni.py"), "list"],
                           capture_output=True, text=True, cwd=ROOT, timeout=30)
        return {"content": [{"type": "text", "text": r.stdout[:5000]}]}

    if name == "omni_run":
        cmd = [sys.executable, str(ROOT / "omni.py"), "run", args["category"],
               args["module"], "--target", args["target"]]
        for x in args.get("extra", []):
            cmd.extend(["--extra", x])
        r = subprocess.run(cmd, capture_output=True, text=True,
                           cwd=ROOT, timeout=300)
        return {"content": [{"type": "text", "text": r.stdout[-5000:]}]}

    if name == "omni_chain":
        r = subprocess.run(
            [sys.executable, str(ROOT / "omni.py"), "chain", args["chain"],
             "--target", args["target"]],
            capture_output=True, text=True, cwd=ROOT, timeout=1800)
        return {"content": [{"type": "text", "text": r.stdout[-5000:]}]}

    if name == "omni_chameleon":
        r = subprocess.run(
            [sys.executable, str(ROOT / "omni.py"), "run", "evasion", "chameleon_mode",
             "--target", args["target"]],
            capture_output=True, text=True, cwd=ROOT, timeout=120)
        return {"content": [{"type": "text", "text": r.stdout[-3000:]}]}

    if name == "omni_cve_lookup":
        sys.path.insert(0, str(ROOT))
        from core.cve_db import enrich
        info = enrich(args["cve_id"])
        return {"content": [{"type": "text", "text": json.dumps(info, indent=2)}]}

    return {"error": f"unknown tool: {name}"}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        method = msg.get("method")
        params = msg.get("params", {})
        msg_id = msg.get("id")

        if method == "tools/list":
            result = list_tools()
        elif method == "tools/call":
            result = call_tool(params.get("name"), params.get("arguments", {}))
        elif method == "initialize":
            result = {"protocolVersion": "2024-11-05",
                      "capabilities": {"tools": {}},
                      "serverInfo": {"name": "omnistrike", "version": "2.0"}}
        else:
            result = {"error": "unknown method"}

        resp = {"jsonrpc": "2.0", "id": msg_id, "result": result}
        print(json.dumps(resp), flush=True)


if __name__ == "__main__":
    main()
