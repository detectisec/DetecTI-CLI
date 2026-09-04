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
        sub_id = conn.execute("SELECT id FROM subdomains LIMIT 1").fetchone()[0]
        
    print(f"Testing build_graph with active target UUID {sub_id}...")
    res = builder.build_graph(active_targets=[str(sub_id)])
    dom_node = next((n for n in res["elements"]["nodes"] if n["data"]["type"] in ("domain", "subdomain") and n["data"].get("is_target")), None)
    print(f"Node found: {dom_node is not None}")
except Exception as e:
    import traceback
    traceback.print_exc()
