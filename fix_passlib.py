import re

path = "core/database/config_db.py"
with open(path, "r") as f:
    content = f.read()

# Mock bcrypt.__about__ to suppress the passlib warning
mock_code = '''import logging
import sqlite3
import hashlib
from pathlib import Path

# Suppress passlib bcrypt warning
try:
    import bcrypt
    if not hasattr(bcrypt, "__about__"):
        class AboutMock:
            __version__ = bcrypt.__version__
        bcrypt.__about__ = AboutMock()
except ImportError:
    pass

from passlib.context import CryptContext'''

content = content.replace('''import sqlite3
import hashlib
from pathlib import Path
from passlib.context import CryptContext''', mock_code)

with open(path, "w") as f:
    f.write(content)
