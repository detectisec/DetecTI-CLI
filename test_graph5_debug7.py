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

dom_nodes, dom_edges, _, _, _, explicit_targets = builder._build_domain_nodes(conn, active_targets=[str(sub_id)])
print(f"Nodes length: {len(dom_nodes)}")
