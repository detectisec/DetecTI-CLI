"""REST API routes for DetecTI-CLI EASM dashboard."""

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.requests import Request
from pydantic import BaseModel

from core.database.storage import DatabaseManager
from reporters.html_reporter import HTMLReporter
from reporters.json_reporter import JSONReporter
from reporters.markdown_reporter import MarkdownReporter
from .graph_builder import GraphBuilder

router = APIRouter()


def get_db_manager(request: Request) -> Optional[DatabaseManager]:
    """Dependency to get database manager from app state."""
    return getattr(request.app.state, "db_manager", None)


class SelectDbRequest(BaseModel):
    name: str


@router.get("/databases")
async def list_databases(request: Request) -> Dict:
    """List all available SQLite databases in ./data/dbs/ and return the currently active one."""
    data_dir = Path.cwd() / "data" / "dbs"
    databases = []
    
    current_db_path = getattr(request.app.state, "db_path", None)
    current_db_name = Path(current_db_path).name if current_db_path else None
    
    if data_dir.exists():
        for db_file in sorted(data_dir.glob("*.sqlite")):
            size_mb = db_file.stat().st_size / (1024 * 1024)
            mod_time = datetime.fromtimestamp(db_file.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            
            target = "Unknown"
            try:
                dm = DatabaseManager(db_file)
                stats = dm.get_summary_stats()
                if "target" in stats:
                    target = stats["target"]
            except Exception:
                pass
            
            databases.append({
                "name": db_file.name,
                "target": target,
                "size_mb": round(size_mb, 2),
                "modified": mod_time,
                "is_current": (db_file.name == current_db_name)
            })
    
    return {
        "current_db": current_db_name,
        "databases": databases
    }


@router.post("/databases/select")
async def select_database(req: SelectDbRequest, request: Request) -> Dict:
    """Switch active SQLite database in the web dashboard."""
    db_name = req.name
    if not db_name.endswith(".sqlite"):
        db_name += ".sqlite"
        
    db_file = Path.cwd() / "data" / "dbs" / db_name
    if not db_file.exists():
        # Check absolute path
        abs_file = Path(req.name)
        if abs_file.exists() and abs_file.suffix == ".sqlite":
            db_file = abs_file
        else:
            raise HTTPException(status_code=404, detail=f"Database '{req.name}' not found")
    
    # Switch database in app state
    request.app.state.db_manager = DatabaseManager(db_file)
    request.app.state.db_path = str(db_file.resolve())
    
    return {
        "success": True,
        "current_db": db_file.name,
        "db_path": str(db_file.resolve())
    }


@router.get("/summary")
async def get_summary(db: Optional[DatabaseManager] = Depends(get_db_manager)) -> Dict:
    """Get high-level metrics for dashboard sidebar."""
    if not db or not Path(db.db_path).exists():
        return {
            "target": "No Database Selected",
            "total_domains": 0,
            "total_subdomains": 0,
            "total_ips": 0,
            "open_services": 0,
            "total_vulnerabilities": 0,
            "cisa_kev_count": 0,
            "high_epss_count": 0,
            "no_db": True
        }
    
    try:
        stats = db.get_summary_stats()
        
        target_name = "Unknown"
        try:
            import sqlite3
            with sqlite3.connect(db.db_path) as conn:
                cursor = conn.execute("SELECT target FROM scan_results ORDER BY created_at DESC LIMIT 1")
                row = cursor.fetchone()
                if row:
                    target_name = row[0]
                else:
                    first_domain = conn.execute("SELECT name FROM domains LIMIT 1").fetchone()
                    if first_domain:
                        target_name = first_domain[0]
                    else:
                        first_ip = conn.execute("SELECT ip FROM ip_addresses LIMIT 1").fetchone()
                        if first_ip:
                            target_name = first_ip[0]
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
            "high_epss_count": stats.get("high_epss_count", 0),
            "no_db": False
        }
    except Exception as e:
        print(f"Summary API error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get summary: {str(e)}")


@router.get("/graph")
async def get_graph_data(db: Optional[DatabaseManager] = Depends(get_db_manager)) -> Dict:
    """Generate Cytoscape.js graph data from database."""
    if not db or not Path(db.db_path).exists():
        return {"elements": {"nodes": [], "edges": []}}
        
    try:
        builder = GraphBuilder(db)
        graph_data = builder.build_graph()
        return graph_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to build graph: {str(e)}")


@router.get("/assets")
async def get_assets(db: Optional[DatabaseManager] = Depends(get_db_manager)) -> List[Dict]:
    """Get detailed asset list for tabular view."""
    if not db or not Path(db.db_path).exists():
        return []
        
    try:
        import sqlite3
        assets = []
        
        with sqlite3.connect(db.db_path) as conn:
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


@router.get("/export")
async def export_graph_data(
    format: str = Query("json", pattern="^(json|markdown|md|html)$"),
    db: Optional[DatabaseManager] = Depends(get_db_manager)
):
    """Export current scan results in JSON, Markdown or HTML format, matching CLI export structure."""
    if not db or not Path(db.db_path).exists():
        raise HTTPException(status_code=400, detail="No active database to export")
    
    try:
        scan_result = db.reconstruct_scan_result()
        if not scan_result:
            raise HTTPException(status_code=404, detail="No scan results found in the active database")
        
        safe_target = "".join(c if c.isalnum() else "_" for c in scan_result.target)[:40]
        timestamp = scan_result.started_at.strftime("%Y%m%d_%H%M%S")
        
        if format in ("markdown", "md"):
            md_content = MarkdownReporter.generate(scan_result)
            filename = f"detecti_{safe_target}_{timestamp}.md"
            return Response(
                content=md_content,
                media_type="text/markdown; charset=utf-8",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"'
                }
            )
        elif format == "html":
            html_content = HTMLReporter.generate(scan_result)
            filename = f"detecti_{safe_target}_{timestamp}.html"
            return Response(
                content=html_content,
                media_type="text/html; charset=utf-8",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"'
                }
            )
        else:
            json_content = JSONReporter.generate(scan_result)
            filename = f"detecti_{safe_target}_{timestamp}.json"
            return Response(
                content=json_content,
                media_type="application/json; charset=utf-8",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"'
                }
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")


