import re
from pathlib import Path

# Fix utils/setup.py
path1 = "utils/setup.py"
with open(path1, "r") as f:
    c1 = f.read()

c1 = c1.replace(
    'config_db = ConfigDBManager(db_dir / "config.sqlite")',
    'config_db = ConfigDBManager(self.root_dir / "data" / "config.sqlite")'
)

with open(path1, "w") as f:
    f.write(c1)

# Fix web/api/auth.py
path2 = "web/api/auth.py"
with open(path2, "r") as f:
    c2 = f.read()

c2 = c2.replace(
    'db_path = Path.cwd() / "data" / "dbs" / "config.sqlite"',
    'db_path = Path.cwd() / "data" / "config.sqlite"'
)

with open(path2, "w") as f:
    f.write(c2)

