from web.api.graph_builder import GraphBuilder
import glob, sqlite3

class DummyDB:
    @property
    def db_path(self):
        dbs = glob.glob("data/dbs/*.sqlite")
        return dbs[0]

builder = GraphBuilder(DummyDB())
with sqlite3.connect(DummyDB().db_path) as conn:
    sub_id = conn.execute("SELECT id FROM subdomains LIMIT 1").fetchone()[0]

print(f"Target UUID: {sub_id}")
res = builder.build_graph(active_targets=[str(sub_id)])
for n in res["elements"]["nodes"]:
    print(n["data"]["id"], n["data"]["type"])
