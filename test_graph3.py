from web.api.graph_builder import GraphBuilder
import sqlite3
import glob

class DummyDB:
    @property
    def db_path(self):
        dbs = glob.glob("data/dbs/*.sqlite")
        return dbs[0]

builder = GraphBuilder(DummyDB())
try:
    print("Testing build_graph with UUID target...")
    # Fetch a UUID
    with sqlite3.connect(DummyDB().db_path) as conn:
        dom_id = conn.execute("SELECT id FROM domains LIMIT 1").fetchone()[0]
    print(f"Domain UUID: {dom_id}")
    res = builder.build_graph(active_targets=[str(dom_id)])
    print("Success, nodes count:", len(res["elements"]["nodes"]))
    
    # Check if dom_id is in nodes
    dom_found = any(n["data"]["id"] == f"dom_{dom_id}" for n in res["elements"]["nodes"])
    print(f"Domain Node Spawned: {dom_found}")
except Exception as e:
    import traceback
    traceback.print_exc()
