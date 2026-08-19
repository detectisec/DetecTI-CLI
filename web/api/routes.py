"""REST API routes for DetecTI-CLI EASM dashboard."""

from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException
from fastapi.requests import Request

from core.database.storage import DatabaseManager
from .graph_builder import GraphBuilder

router = APIRouter()


def get_db_manager(request: Request) -> DatabaseManager:
    """Dependency to get database manager from app state."""
    return request.app.state.db_manager


@router.get("/summary")
async def get_summary(db: DatabaseManager = Depends(get_db_manager)) -> Dict:
    """Get high-level metrics for dashboard sidebar."""
    try:
        stats = db.get_summary_stats()
        
        # Get target name from database
        target_name = "Unknown"
        try:
            import sqlite3
            with sqlite3.connect(db.db_path) as conn:
                cursor = conn.execute("SELECT target FROM scan_results ORDER BY created_at DESC LIMIT 1")
                row = cursor.fetchone()
                if row:
                    target_name = row[0]
        except Exception as e:
            print(f"Error getting target name: {e}")
        
        return {
            "target": target_name,
            "total_domains": stats.get("total_domains", 0),
            "total_subdomains": stats.get("total_subdomains", 0),
            "total_ips": stats.get("total_ips", 0),
            "open_services": stats.get("open_services", 0),
            "total_vulnerabilities": stats.get("total_vulnerabilities", 0),
            "cisa_kev_count": stats.get("cisa_kev_count", 0),
            "high_epss_count": stats.get("high_epss_count", 0)
        }
    except Exception as e:
        print(f"Summary API error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get summary: {str(e)}")


@router.get("/graph")
async def get_graph_data(db: DatabaseManager = Depends(get_db_manager)) -> Dict:
    """Generate Cytoscape.js graph data from database."""
    try:
        builder = GraphBuilder(db)
        graph_data = builder.build_graph()
        return graph_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to build graph: {str(e)}")


@router.get("/leads")
async def get_leads(db: DatabaseManager = Depends(get_db_manager)) -> List[Dict]:
    """Get lead targets (IPs and domains) with vulnerability indicators for the Lead Selector."""
    try:
        import sqlite3
        leads = []
        
        with sqlite3.connect(db.db_path) as conn:
            conn.row_factory = sqlite3.Row  # Enable column access by name
            
            # First, get all IPs with their vulnerability indicators
            cursor = conn.execute("""
                SELECT 
                    ip.ip,
                    COALESCE(ip.org, 'Unknown') as org,
                    COALESCE(ip.country, 'Unknown') as country,
                    COUNT(DISTINCT s.id) as service_count,
                    COUNT(DISTINCT v.id) as vuln_count,
                    MAX(CASE WHEN v.is_cisa_kev = 1 THEN 1 ELSE 0 END) as has_kev,
                    MAX(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) as has_critical,
                    COALESCE(SUM(CASE WHEN v.exploit_count > 0 THEN 1 ELSE 0 END), 0) as poc_count
                FROM ip_addresses ip
                LEFT JOIN services s ON ip.id = s.ip_id
                LEFT JOIN vulnerabilities v ON ip.id = v.ip_id
                GROUP BY ip.id, ip.ip, ip.org, ip.country
                ORDER BY has_kev DESC, has_critical DESC, vuln_count DESC, service_count DESC
            """)
            
            rows = cursor.fetchall()
            print(f"Found {len(rows)} IP addresses")
            
            for row in rows:
                lead = {
                    "id": f"ip_{row['ip']}",
                    "type": "ip",
                    "name": row['ip'],
                    "display_name": row['ip'],
                    "org": row['org'],
                    "country": row['country'],
                    "service_count": row['service_count'],
                    "vuln_count": row['vuln_count'],
                    "has_kev": bool(row['has_kev']),
                    "has_critical": bool(row['has_critical']),
                    "poc_count": row['poc_count']
                }
                leads.append(lead)
                print(f"Added IP lead: {lead}")
            
            # Then get all domains with their vulnerability indicators
            cursor = conn.execute("""
                SELECT DISTINCT
                    d.name,
                    COUNT(DISTINCT ip.id) as ip_count,
                    COUNT(DISTINCT s.id) as service_count,
                    COUNT(DISTINCT v.id) as vuln_count,
                    MAX(CASE WHEN v.is_cisa_kev = 1 THEN 1 ELSE 0 END) as has_kev,
                    MAX(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) as has_critical,
                    COALESCE(SUM(CASE WHEN v.exploit_count > 0 THEN 1 ELSE 0 END), 0) as poc_count
                FROM domains d
                LEFT JOIN subdomains sd ON d.id = sd.domain_id
                LEFT JOIN ip_addresses ip ON sd.ip_id = ip.id OR d.ip_id = ip.id
                LEFT JOIN services s ON ip.id = s.ip_id
                LEFT JOIN vulnerabilities v ON ip.id = v.ip_id
                WHERE d.name IS NOT NULL
                GROUP BY d.id, d.name
                HAVING COUNT(DISTINCT ip.id) > 0
                ORDER BY has_kev DESC, has_critical DESC, vuln_count DESC, service_count DESC
            """)
            
            domain_rows = cursor.fetchall()
            print(f"Found {len(domain_rows)} domains")
            
            for row in domain_rows:
                lead = {
                    "id": f"domain_{row['name']}",
                    "type": "domain",
                    "name": row['name'],
                    "display_name": row['name'],
                    "ip_count": row['ip_count'],
                    "service_count": row['service_count'],
                    "vuln_count": row['vuln_count'],
                    "has_kev": bool(row['has_kev']),
                    "has_critical": bool(row['has_critical']),
                    "poc_count": row['poc_count']
                }
                leads.append(lead)
                print(f"Added domain lead: {lead}")
        
        print(f"Returning {len(leads)} total leads")
        return leads
        
    except Exception as e:
        print(f"Error in get_leads: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to get leads: {str(e)}")


@router.get("/assets")
async def get_assets(db: DatabaseManager = Depends(get_db_manager)) -> List[Dict]:
    """Get detailed asset list for tabular view."""
    try:
        import sqlite3
        assets = []
        
        with sqlite3.connect(db.db_path) as conn:
            # Get all IPs with their metadata
            cursor = conn.execute("""
                SELECT ip.ip, ip.org, ip.country, ip.asn,
                       COUNT(DISTINCT s.id) as service_count,
                       COUNT(DISTINCT v.id) as vuln_count,
                       MAX(CASE WHEN v.is_cisa_kev = 1 THEN 1 ELSE 0 END) as has_kev
                FROM ip_addresses ip
                LEFT JOIN services s ON ip.id = s.ip_id
                LEFT JOIN vulnerabilities v ON ip.id = v.ip_id
                GROUP BY ip.id, ip.ip, ip.org, ip.country, ip.asn
                ORDER BY vuln_count DESC, service_count DESC
            """)
            
            for row in cursor.fetchall():
                assets.append({
                    "type": "ip",
                    "value": row[0],
                    "org": row[1] or "Unknown",
                    "country": row[2] or "Unknown",
                    "asn": row[3] or "Unknown",
                    "services": row[4],
                    "vulnerabilities": row[5],
                    "has_cisa_kev": bool(row[6])
                })
        
        return assets
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get assets: {str(e)}")
