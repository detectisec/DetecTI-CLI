from web.api.graph_builder import GraphBuilder
import glob

class DummyDB:
    @property
    def db_path(self):
        dbs = glob.glob("data/dbs/*.sqlite")
        return dbs[0]

builder = GraphBuilder(DummyDB())
try:
    print("Testing build_graph with target...")
    res = builder.build_graph(active_targets=["131.108.164.18", "example.com"])
    print("Success, nodes count:", len(res["elements"]["nodes"]))
except Exception as e:
    import traceback
    traceback.print_exc()
