import re

with open("web/api/routes.py", "r") as f:
    content = f.read()

target = """@router.get("/graph")
async def get_graph_data(db: Optional[DatabaseManager] = Depends(get_db_manager)) -> Dict:
    \"\"\"Generate Cytoscape.js graph data from database.\"\"\"
    if not db or not Path(db.db_path).exists():
        return {"elements": {"nodes": [], "edges": []}}
        
    try:
        active_target_keys = list(_target_registry.keys())
        builder = GraphBuilder(db)
        graph_data = builder.build_graph(active_targets=active_target_keys)
        return graph_data"""

replacement = """
_auto_targets_loaded = False

@router.get("/graph")
async def get_graph_data(db: Optional[DatabaseManager] = Depends(get_db_manager)) -> Dict:
    \"\"\"Generate Cytoscape.js graph data from database.\"\"\"
    global _auto_targets_loaded
    if not db or not Path(db.db_path).exists():
        return {"elements": {"nodes": [], "edges": []}}
        
    # Auto-Target Logic for small datasets (<= 50 items)
    if not _auto_targets_loaded:
        try:
            with __import__('sqlite3').connect(db.db_path) as conn:
                d_rows = conn.execute("SELECT name FROM domains").fetchall()
                s_rows = conn.execute("SELECT name FROM subdomains").fetchall()
                i_rows = conn.execute("SELECT ip FROM ip_addresses").fetchall()
                
                total_passive = len(d_rows) + len(s_rows) + len(i_rows)
                
                if 0 < total_passive <= 50:
                    for r in (d_rows + s_rows + i_rows):
                        item = r[0]
                        if item and item not in _target_registry:
                            _target_registry[item] = {
                                "ip": item,
                                "status": "idle",
                                "nuclei_status": "idle",
                                "ports_count": 0,
                                "vulns_count": 0,
                                "ports": [],
                                "error": None,
                                "last_scan": None,
                                "last_nuclei_scan": None
                            }
        except Exception:
            pass
        finally:
            _auto_targets_loaded = True
            
    try:
        active_target_keys = list(_target_registry.keys())
        builder = GraphBuilder(db)
        graph_data = builder.build_graph(active_targets=active_target_keys)
        return graph_data"""

content = content.replace(target, replacement)

with open("web/api/routes.py", "w") as f:
    f.write(content)
