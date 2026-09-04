import sqlite3

try:
    with sqlite3.connect("database.sqlite") as conn:
        cursor = conn.execute("SELECT COUNT(*) FROM domains")
        print("Domains:", cursor.fetchone()[0])
except Exception as e:
    print(e)
