"""REST API routes for DetecTI-CLI EASM dashboard."""

import asyncio
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


# ----------------------------------------------------------------------
# Target Management & Active Scan Endpoints
# ----------------------------------------------------------------------

from modules.masscan import MasscanRunner

# In-memory target registry and running tasks tracking
_target_registry: Dict[str, Dict] = {}
_running_scan_tasks: Dict[str, asyncio.Task] = {}
_scan_log_history: List[Dict] = []


class TargetActionRequest(BaseModel):
    ip: str


class ActiveScanRequest(BaseModel):
    targets: Optional[List[str]] = None
    preset: Optional[str] = "top100"
    ports: Optional[str] = "--top-ports 100"
    rate: Optional[int] = 1000
    disable_ping: Optional[bool] = True
    banners: Optional[bool] = True
    custom_flags: Optional[str] = None


class CancelScanRequest(BaseModel):
    target: Optional[str] = None
    all: Optional[bool] = False


def _append_scan_log(level: str, message: str, target: Optional[str] = None):
    entry = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "level": level,
        "message": message,
        "target": target,
    }
    _scan_log_history.append(entry)
    if len(_scan_log_history) > 100:
        _scan_log_history.pop(0)


@router.get("/targets")
async def list_targets() -> Dict:
    """List all currently marked IP targets with their scan statuses."""
    return {
        "targets": list(_target_registry.values()),
        "count": len(_target_registry),
    }


@router.post("/targets/set")
async def set_target(req: TargetActionRequest) -> Dict:
    """Mark an IP address as an active target."""
    ip = req.ip.strip()
    if not ip:
        raise HTTPException(status_code=400, detail="Invalid IP address")
    
    if ip not in _target_registry:
        _target_registry[ip] = {
            "ip": ip,
            "status": "idle",
            "ports_count": 0,
            "ports": [],
            "error": None,
            "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_scan": None,
        }
        _append_scan_log("info", f"IP {ip} added to active targets.", target=ip)
    
    return {
        "success": True,
        "target": _target_registry[ip],
        "total_targets": len(_target_registry),
    }


@router.post("/targets/remove")
async def remove_target(req: TargetActionRequest) -> Dict:
    """Remove an IP address from the marked targets list."""
    ip = req.ip.strip()
    if ip in _running_scan_tasks:
        task = _running_scan_tasks[ip]
        if not task.done():
            task.cancel()
        _running_scan_tasks.pop(ip, None)

    if ip in _target_registry:
        del _target_registry[ip]
        _append_scan_log("info", f"IP {ip} removed from targets.", target=ip)
    
    return {
        "success": True,
        "removed": ip,
        "total_targets": len(_target_registry),
    }


@router.post("/targets/clear")
async def clear_all_targets() -> Dict:
    """Remove all targets and cancel running scans."""
    for ip, task in list(_running_scan_tasks.items()):
        if not task.done():
            task.cancel()
    _running_scan_tasks.clear()
    count = len(_target_registry)
    _target_registry.clear()
    _append_scan_log("info", "All targets cleared.")
    return {
        "success": True,
        "cleared_count": count,
    }


@router.get("/scan/check-permissions")
async def check_scan_permissions() -> Dict:
    """Verify Masscan binary availability and execution permissions."""
    runner = MasscanRunner()
    return runner.check_permissions()


@router.post("/scan/active")
async def start_active_scan(
    req: ActiveScanRequest,
    request: Request,
    db: Optional[DatabaseManager] = Depends(get_db_manager),
) -> Dict:
    """Start asynchronous Masscan port scan on designated targets or all marked targets."""
    runner = MasscanRunner()
    perm = runner.check_permissions()
    if not perm["available"]:
        raise HTTPException(
            status_code=400,
            detail="Masscan executable not found on server. Install Masscan to run active scans.",
        )

    # Determine targets to scan
    target_ips = req.targets if req.targets else list(_target_registry.keys())
    if not target_ips:
        raise HTTPException(status_code=400, detail="No targets selected for active scan.")

    # Ensure all targets exist in registry
    for ip in target_ips:
        if ip not in _target_registry:
            _target_registry[ip] = {
                "ip": ip,
                "status": "idle",
                "ports_count": 0,
                "ports": [],
                "error": None,
                "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_scan": None,
            }

    # Resolve port parameters based on preset
    ports_arg = req.ports
    if req.preset == "top100":
        ports_arg = "--top-ports 100"
    elif req.preset == "all":
        ports_arg = "-p0-65535"
    elif req.preset == "web":
        ports_arg = "-p80,443,8080,8443,8000,8888,9000,9443"

    async def _run_single_target_scan(ip_to_scan: str):
        _target_registry[ip_to_scan]["status"] = "scanning"
        _target_registry[ip_to_scan]["error"] = None
        _append_scan_log("info", f"Starting active scan on {ip_to_scan} ({ports_arg}, rate={req.rate})...", target=ip_to_scan)

        try:
            scan_res = await runner.scan_target(
                target_ip=ip_to_scan,
                ports=ports_arg,
                rate=req.rate or 1000,
                disable_ping=req.disable_ping if req.disable_ping is not None else True,
                banners=req.banners if req.banners is not None else True,
                custom_flags=req.custom_flags,
            )

            if scan_res.get("success"):
                open_ports = scan_res.get("ports", [])
                _target_registry[ip_to_scan]["status"] = "completed"
                _target_registry[ip_to_scan]["ports_count"] = len(open_ports)
                _target_registry[ip_to_scan]["ports"] = open_ports
                _target_registry[ip_to_scan]["last_scan"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Resolve active database manager dynamically and persist discovered services
                active_db = getattr(request.app.state, "db_manager", None) or db
                if not active_db or not Path(active_db.db_path).exists():
                    dbs_dir = Path.cwd() / "data" / "dbs"
                    if dbs_dir.exists():
                        existing_dbs = sorted(list(dbs_dir.glob("*.sqlite")))
                        if existing_dbs:
                            active_db = DatabaseManager(existing_dbs[0])
                            request.app.state.db_manager = active_db
                            request.app.state.db_path = str(existing_dbs[0].resolve())

                if active_db and Path(active_db.db_path).exists():
                    merge_info = active_db.merge_active_scan_services(ip_to_scan, open_ports)
                    _append_scan_log(
                        "success",
                        f"Scan on {ip_to_scan} completed: {len(open_ports)} port(s) found. Persisted to database ({merge_info.get('added_services', 0)} new, {merge_info.get('updated_services', 0)} verified).",
                        target=ip_to_scan,
                    )
                else:
                    _append_scan_log(
                        "success",
                        f"Scan on {ip_to_scan} completed: {len(open_ports)} open port(s) discovered.",
                        target=ip_to_scan,
                    )
            else:
                err_msg = scan_res.get("error", "Unknown scan error")
                _target_registry[ip_to_scan]["status"] = "failed"
                _target_registry[ip_to_scan]["error"] = err_msg
                _append_scan_log("error", f"Scan on {ip_to_scan} failed: {err_msg}", target=ip_to_scan)

        except asyncio.CancelledError:
            _target_registry[ip_to_scan]["status"] = "idle"
            _append_scan_log("warning", f"Scan on {ip_to_scan} was cancelled by user.", target=ip_to_scan)
        except Exception as ex:
            _target_registry[ip_to_scan]["status"] = "failed"
            _target_registry[ip_to_scan]["error"] = str(ex)
            _append_scan_log("error", f"Unexpected error scanning {ip_to_scan}: {str(ex)}", target=ip_to_scan)
        finally:
            _running_scan_tasks.pop(ip_to_scan, None)

    # Spawn background task for each target
    for ip in target_ips:
        # Cancel previous running task on same IP if exists
        if ip in _running_scan_tasks and not _running_scan_tasks[ip].done():
            _running_scan_tasks[ip].cancel()
        
        task = asyncio.create_task(_run_single_target_scan(ip))
        _running_scan_tasks[ip] = task

    return {
        "success": True,
        "message": f"Active scan dispatched for {len(target_ips)} target(s).",
        "targets": target_ips,
        "ports": ports_arg,
    }


@router.post("/scan/cancel")
async def cancel_active_scan(req: CancelScanRequest) -> Dict:
    """Cancel running active scan for a specific target or all targets."""
    cancelled = []
    if req.all or not req.target:
        for ip, task in list(_running_scan_tasks.items()):
            if not task.done():
                task.cancel()
                cancelled.append(ip)
                if ip in _target_registry:
                    _target_registry[ip]["status"] = "idle"
        _running_scan_tasks.clear()
        _append_scan_log("info", "All active scans cancelled.")
    else:
        ip = req.target.strip()
        if ip in _running_scan_tasks:
            task = _running_scan_tasks[ip]
            if not task.done():
                task.cancel()
                cancelled.append(ip)
            _running_scan_tasks.pop(ip, None)
            if ip in _target_registry:
                _target_registry[ip]["status"] = "idle"
            _append_scan_log("info", f"Active scan on {ip} cancelled.", target=ip)

    return {
        "success": True,
        "cancelled_targets": cancelled,
    }


@router.get("/scan/status")
async def get_scan_status() -> Dict:
    """Get real-time scan status, target registry, and recent activity logs."""
    running_count = sum(1 for t in _target_registry.values() if t.get("status") == "scanning")
    return {
        "running_scans": running_count,
        "targets": list(_target_registry.values()),
        "total_targets": len(_target_registry),
        "recent_logs": _scan_log_history[-30:],
    }



