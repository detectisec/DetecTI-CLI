import re

with open("web/api/routes.py", "r") as f:
    content = f.read()

target = """_auto_targets_loaded = False

@router.get("/graph")
async def get_graph_data(db: Optional[DatabaseManager] = Depends(get_db_manager)) -> Dict:
    \"\"\"Generate Cytoscape.js graph data from database.\"\"\"
    global _auto_targets_loaded
    if not db or not Path(db.db_path).exists():
        return {"elements": {"nodes": [], "edges": []}}
        
    # Auto-Target Logic for small datasets (<= 50 items)
    if not _auto_targets_loaded:
        try:"""

replacement = """_auto_targets_loaded = set()

@router.get("/graph")
async def get_graph_data(db: Optional[DatabaseManager] = Depends(get_db_manager)) -> Dict:
    \"\"\"Generate Cytoscape.js graph data from database.\"\"\"
    global _auto_targets_loaded
    if not db or not Path(db.db_path).exists():
        return {"elements": {"nodes": [], "edges": []}}
        
    # Auto-Target Logic for small datasets (<= 50 items)
    if db.db_path not in _auto_targets_loaded:
        try:"""

content = content.replace(target, replacement)

target2 = """        except Exception:
            pass
        finally:
            _auto_targets_loaded = True"""

replacement2 = """        except Exception:
            pass
        finally:
            _auto_targets_loaded.add(db.db_path)"""

content = content.replace(target2, replacement2)

with open("web/api/routes.py", "w") as f:
    f.write(content)
