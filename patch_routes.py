import re

with open("web/api/routes.py", "r") as f:
    content = f.read()

target = '@router.get("/graph")\nasync def get_graph(db: DatabaseManager = Depends(get_db)):\n    """Fetch complete graph data."""\n    builder = GraphBuilder(db)\n    active_target_keys = list(_target_registry.keys())\n    return builder.build_graph(active_targets=active_target_keys)'

replacement = '''
_auto_targets_loaded = False

@router.get("/graph")
async def get_graph(db: DatabaseManager = Depends(get_db)):
    """Fetch complete graph data."""
    global _auto_targets_loaded
    
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
        except Exception as e:
            pass
        finally:
            _auto_targets_loaded = True
            
    builder = GraphBuilder(db)
    active_target_keys = list(_target_registry.keys())
    return builder.build_graph(active_targets=active_target_keys)'''

content = content.replace(target, replacement)

with open("web/api/routes.py", "w") as f:
    f.write(content)
