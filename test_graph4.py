from web.api.graph_builder import GraphBuilder
import glob, sqlite3

class DummyDB:
    @property
    def db_path(self):
        dbs = glob.glob("data/dbs/*.sqlite")
        return dbs[0]

builder = GraphBuilder(DummyDB())
try:
    with sqlite3.connect(DummyDB().db_path) as conn:
        sub_name = conn.execute("SELECT name FROM subdomains LIMIT 1").fetchone()[0]
        
    print(f"Testing build_graph with active target {sub_name}...")
    res = builder.build_graph(active_targets=[sub_name])
    dom_node = next(n for n in res["elements"]["nodes"] if n["data"]["type"] in ("domain", "subdomain") and n["data"].get("is_target"))
    print(f"Node: {dom_node['data']['label']}")
    print(f"Passive IPs: {len(dom_node['data'].get('passive_ips', []))}")
    print(f"Passive Services: {len(dom_node['data'].get('passive_services', []))}")
    print(f"Passive Vulns: {len(dom_node['data'].get('passive_vulns', []))}")
except Exception as e:
    import traceback
    traceback.print_exc()
