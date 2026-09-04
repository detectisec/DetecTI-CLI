import sqlite3
import hashlib
from pathlib import Path
from passlib.context import CryptContext
from pydantic_settings import BaseSettings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

class ConfigDBManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'admin',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()

    def create_user(self, username: str, password_hash: str, role: str = 'admin'):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO users (username, password_hash, role)
                    VALUES (?, ?, ?)
                ''', (username, password_hash, role))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False

    def update_user_password(self, username: str, password_hash: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                UPDATE users SET password_hash = ? WHERE username = ?
            ''', (password_hash, username))
            conn.commit()

    def get_user(self, username: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
            return cursor.fetchone()

    def user_exists(self, username: str) -> bool:
        return self.get_user(username) is not None

