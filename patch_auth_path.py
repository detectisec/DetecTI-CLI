import re

path = "web/api/auth.py"
with open(path, "r") as f:
    content = f.read()

new_func = '''def get_config_db():
    from pathlib import Path
    project_root = Path(__file__).parent.parent.parent
    db_path = project_root / "data" / "config.sqlite"
    return ConfigDBManager(db_path)'''

content = re.sub(r'def get_config_db\(\):[\s\S]*?return ConfigDBManager\(db_path\)', new_func, content)

with open(path, "w") as f:
    f.write(content)
