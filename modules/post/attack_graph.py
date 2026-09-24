"""attack_graph — BAS: build reachability graph from given hosts + credentials"""
import json
from pathlib import Path
from core.http import HttpClient


class AttackGraph:
    def run(self, session, logger):
        """
        Input JSON in --extra graph=path.json:
        {
          "hosts": [
            {"ip": "10.0.0.1", "services": ["ssh:22"], "creds": [["root","toor"]]},
            {"ip": "10.0.0.2", "services": ["http:80", "ssh:22"]},
            {"ip": "10.0.0.5", "services": ["smb:445", "rdp:3389"]}
          ],
          "entry": "10.0.0.1",
          "target": "10.0.0.5"
        }
        Output: JSON with attack paths, reachable hosts, critical nodes.
        NO real requests. Graph analysis only.
        """
        graph_path = None
        for x in session.extra:
            if x.startswith("graph="):
                graph_path = x.split("=", 1)[1]

        if not graph_path or not Path(graph_path).is_file():
            print("[attack_graph] provide --extra graph=path.json")
            print("  example:")
            print(json.dumps({
                "hosts": [
                    {"ip": "10.0.0.1", "services": ["ssh:22"], "creds": [["root","toor"]]},
                    {"ip": "10.0.0.2", "services": ["http:80"]},
                    {"ip": "10.0.0.5", "services": ["smb:445", "rdp:3389"]}
                ],
                "entry": "10.0.0.1",
                "target": "10.0.0.5"
            }, indent=2))
            return {}

        data = json.loads(Path(graph_path).read_text())
        hosts = {h["ip"]: h for h in data["hosts"]}
        entry = data.get("entry")
        target = data.get("target")

        print(f"[attack_graph] {len(hosts)} hosts, entry={entry}, target={target}")

        # build reachability edges
        # rule: from host A with creds C you can reach host B if B has a service
        # that accepts C (ssh with creds, smb with creds, rdp with creds)
        edges = []
        for a_ip, a in hosts.items():
            for cred in a.get("creds", []):
                for b_ip, b in hosts.items():
                    if a_ip == b_ip:
                        continue
                    # check services
                    for svc in b.get("services", []):
                        svc_name = svc.split(":")[0]
                        # creds work on ssh, smb, rdp, winrm, http-basic
                        if svc_name in ("ssh", "smb", "rdp", "winrm", "telnet"):
                            edges.append({
                                "from": a_ip, "to": b_ip,
                                "via": svc, "cred": cred,
                            })

        print(f"[attack_graph] {len(edges)} edges")

        # BFS from entry
        reachable = {entry}
        frontier = {entry}
        paths = {entry: [[entry]]}
        while frontier:
            next_frontier = set()
            for cur in frontier:
                for e in edges:
                    if e["from"] == cur and e["to"] not in reachable:
                        reachable.add(e["to"])
                        next_frontier.add(e["to"])
                        for p in paths.get(cur, [[cur]]):
                            paths.setdefault(e["to"], []).append(p + [e["to"]])
            frontier = next_frontier

        print(f"[attack_graph] reachable from entry: {sorted(reachable)}")
        if target:
            if target in reachable:
                print(f"  ✓ TARGET {target} REACHABLE")
                for p in paths.get(target, [])[:5]:
                    print(f"    path: {' -> '.join(p)}")
                logger.finding("attack_graph", "critical",
                               f"target {target} reachable from {entry}")
            else:
                print(f"  ✗ target {target} NOT reachable")
                logger.finding("attack_graph", "info",
                               f"target {target} not reachable")

        # critical nodes (high betweenness)
        in_degree = {}
        for e in edges:
            in_degree[e["to"]] = in_degree.get(e["to"], 0) + 1
        critical = sorted(in_degree.items(), key=lambda x: -x[1])[:5]
        print(f"[attack_graph] critical nodes: {critical}")

        out = {
            "reachable": sorted(reachable),
            "target_reachable": target in reachable if target else None,
            "paths_to_target": paths.get(target, [])[:10] if target else [],
            "critical_nodes": critical,
            "edges": edges,
        }
        (Path("reports") / "attack_graph.json").parent.mkdir(parents=True, exist_ok=True)
        (Path("reports") / "attack_graph.json").write_text(json.dumps(out, indent=2))
        print(f"[attack_graph] saved -> reports/attack_graph.json")
        logger.finding("attack_graph", "info",
                       f"{len(reachable)} reachable, {len(edges)} edges")
        return out
