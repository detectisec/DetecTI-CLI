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

print(f"Target UUID: {sub_id}")

cursor_subs = conn.execute("""
    SELECT s.id, s.name, s.domain_id, d.name, i.id, i.ip
    FROM subdomains s
    JOIN domains d ON s.domain_id = d.id
    LEFT JOIN subdomain_resolutions sr ON s.id = sr.subdomain_id
    LEFT JOIN ip_addresses i ON sr.ip_id = i.id
    ORDER BY s.name ASC
""")
rows = cursor_subs.fetchall()
print(f"Query returned {len(rows)} rows")
for row in rows:
    if row[0] == sub_id:
        print(f"Found in query: {row}")
        break

