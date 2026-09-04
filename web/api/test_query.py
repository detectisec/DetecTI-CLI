import sqlite3
import json
import sys

def get_db():
    import glob
    dbs = glob.glob("data/dbs/*.sqlite")
    if not dbs:
        return None
    return dbs[0]

db_path = get_db()
if not db_path:
    print("No db found")
    sys.exit(0)

with sqlite3.connect(db_path) as conn:
    cursor = conn.execute("""
        SELECT ip.id, ip.ip,
               COUNT(DISTINCT s.id) as service_count,
               COUNT(DISTINCT CASE WHEN s.sources LIKE '%masscan%' OR s.sources LIKE '%active%' THEN s.id END) as verified_service_count,
               COUNT(DISTINCT v.id) as vuln_count,
               MAX(CASE WHEN v.is_cisa_kev = 1 THEN 1 ELSE 0 END) as has_kev,
               COUNT(DISTINCT CASE WHEN v.is_cisa_kev = 1 THEN v.id END) as kev_count,
               COUNT(DISTINCT CASE WHEN v.severity = 'CRITICAL' THEN v.id END) as critical_count,
               COUNT(DISTINCT CASE WHEN v.severity = 'HIGH' THEN v.id END) as high_count,
               MAX(v.epss_score) as max_epss,
               COUNT(DISTINCT CASE WHEN v.epss_score >= 0.20 THEN v.id END) as high_epss_count,
               COUNT(DISTINCT e.id) as poc_count
        FROM ip_addresses ip
        LEFT JOIN services s ON ip.id = s.ip_id
        LEFT JOIN vulnerabilities v ON ip.id = v.ip_id OR s.id = v.service_id
        LEFT JOIN exploits e ON v.id = e.vulnerability_id
        GROUP BY ip.id, ip.ip
        LIMIT 5
    """)
    for row in cursor.fetchall():
        print(row)
