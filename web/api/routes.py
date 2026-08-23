"""REST API routes for DetecTI-CLI EASM dashboard."""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

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
from modules.nuclei import NucleiRunner

# In-memory target registry and running tasks tracking
_target_registry: Dict[str, Dict] = {}
_running_scan_tasks: Dict[str, asyncio.Task] = {}
_running_nuclei_tasks: Dict[str, asyncio.Task] = {}
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


class NucleiScanRequest(BaseModel):
    targets: Optional[List[str]] = None
    severities: Optional[List[str]] = ["critical", "high"]
    tags: Optional[List[str]] = None
    custom_tags: Optional[str] = None
    rate_limit: Optional[int] = 150
    concurrency: Optional[int] = 25
    custom_flags: Optional[str] = None


class CancelScanRequest(BaseModel):
    target: Optional[str] = None
    all: Optional[bool] = False
    scan_type: Optional[str] = "all"  # 'masscan', 'nuclei', or 'all'


def _append_scan_log(level: str, message: str, target: Optional[str] = None):
    entry = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "level": level,
        "message": message,
        "target": target,
    }
    _scan_log_history.append(entry)
    if len(_scan_log_history) > 150:
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
            "nuclei_status": "idle",
            "ports_count": 0,
            "ports": [],
            "vulns_count": 0,
            "error": None,
            "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_scan": None,
            "last_nuclei_scan": None,
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

    if ip in _running_nuclei_tasks:
        task = _running_nuclei_tasks[ip]
        if not task.done():
            task.cancel()
        _running_nuclei_tasks.pop(ip, None)

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

    for ip, task in list(_running_nuclei_tasks.items()):
        if not task.done():
            task.cancel()
    _running_nuclei_tasks.clear()

    count = len(_target_registry)
    _target_registry.clear()
    _append_scan_log("info", "All targets cleared.")
    return {
        "success": True,
        "cleared_count": count,
    }


@router.get("/scan/check-permissions")
async def check_scan_permissions() -> Dict:
    """Verify Masscan and Nuclei binary availability and execution permissions."""
    masscan_runner = MasscanRunner()
    nuclei_runner = NucleiRunner()
    return {
        "masscan": masscan_runner.check_permissions(),
        "nuclei": nuclei_runner.check_permissions(),
        "available": masscan_runner.is_available(),
    }


@router.post("/scan/active")
async def start_active_scan(
    req: ActiveScanRequest,
    request: Request,
    db: Optional[DatabaseManager] = Depends(get_db_manager),
) -> Dict:
    """Trigger background active port scan with Masscan against marked targets."""
    runner = MasscanRunner()
    if not runner.is_available():
        raise HTTPException(
            status_code=503,
            detail="Masscan binary not found on server. Install masscan and grant raw packet capabilities.",
        )

    # Determine targets to scan
    target_ips = req.targets if req.targets else list(_target_registry.keys())
    if not target_ips:
        raise HTTPException(status_code=400, detail="No IP targets selected or marked for scanning.")

    ports_arg = req.ports or "--top-ports 100"
    rate_arg = req.rate or 1000
    pn_arg = req.disable_ping if req.disable_ping is not None else True
    banners_arg = req.banners if req.banners is not None else True
    flags_arg = req.custom_flags

    # Auto-register IPs if not yet marked
    for ip in target_ips:
        if ip not in _target_registry:
            _target_registry[ip] = {
                "ip": ip,
                "status": "idle",
                "nuclei_status": "idle",
                "ports_count": 0,
                "ports": [],
                "vulns_count": 0,
                "error": None,
                "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_scan": None,
                "last_nuclei_scan": None,
            }

    async def _run_single_target_scan(ip_to_scan: str):
        try:
            _target_registry[ip_to_scan]["status"] = "scanning"
            _target_registry[ip_to_scan]["error"] = None
            _append_scan_log("info", f"Starting active scan on {ip_to_scan} ({ports_arg}, {rate_arg} pps)...", target=ip_to_scan)

            scan_res = await runner.scan_target(
                target_ip=ip_to_scan,
                ports=ports_arg,
                rate=rate_arg,
                disable_ping=pn_arg,
                banners=banners_arg,
                custom_flags=flags_arg,
                timeout=180.0,
            )

            if scan_res.get("success"):
                open_ports = scan_res.get("open_ports", [])
                _target_registry[ip_to_scan]["status"] = "completed"
                _target_registry[ip_to_scan]["ports_count"] = len(open_ports)
                _target_registry[ip_to_scan]["ports"] = open_ports
                _target_registry[ip_to_scan]["last_scan"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                active_db = db
                if not active_db or not Path(active_db.db_path).exists():
                    current_db_path = getattr(request.app.state, "db_path", None)
                    if current_db_path and Path(current_db_path).exists():
                        active_db = DatabaseManager(Path(current_db_path))
                        request.app.state.db_manager = active_db
                    else:
                        dbs_dir = Path.cwd() / "data" / "dbs"
                        if dbs_dir.exists():
                            existing_dbs = list(dbs_dir.glob("*.sqlite"))
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


# ----------------------------------------------------------------------
# Nuclei Vulnerability Scan Endpoints
# ----------------------------------------------------------------------

def _get_verified_active_services_for_ip(ip: str, db: Optional[DatabaseManager]) -> List[Dict[str, Any]]:
    """Retrieve only verified active services (discovered/validated by active scan or containing active sources) for a given IP."""
    active_services = []
    if db and Path(db.db_path).exists():
        import sqlite3
        with sqlite3.connect(db.db_path) as conn:
            ip_row = conn.execute("SELECT id FROM ip_addresses WHERE ip = ?", (ip,)).fetchone()
            if ip_row:
                ip_id = ip_row[0]
                services = conn.execute(
                    "SELECT port, protocol, service_name, url, ssl, sources, banner FROM services WHERE ip_id = ?",
                    (ip_id,)
                ).fetchall()
                for port, proto, s_name, s_url, s_ssl, s_sources, s_banner in services:
                    # Parse sources to verify active validation
                    sources_list = []
                    if s_sources:
                        try:
                            sources_list = json.loads(s_sources)
                            if not isinstance(sources_list, list):
                                sources_list = [str(sources_list)]
                        except Exception:
                            sources_list = [s_sources]

                    is_verified_active = any(
                        isinstance(s, str) and ("masscan" in s.lower() or "active" in s.lower() or "nuclei" in s.lower())
                        for s in sources_list
                    ) or bool(s_banner and s_banner.strip())

                    if is_verified_active:
                        active_services.append({
                            "port": port,
                            "protocol": proto or "tcp",
                            "service_name": s_name,
                            "url": s_url,
                            "ssl": bool(s_ssl),
                            "sources": sources_list,
                            "banner": s_banner,
                        })
    return active_services


def _format_nuclei_targets_from_services(ip: str, services: List[Dict[str, Any]]) -> List[str]:
    """Format verified active services into Nuclei endpoint URLs/host-ports."""
    formatted_targets: List[str] = []
    for svc in services:
        port = svc["port"]
        s_url = svc.get("url")
        s_ssl = svc.get("ssl", False)
        if s_url and str(s_url).startswith("http"):
            formatted_targets.append(str(s_url).strip())
        elif s_ssl or port in [443, 8443, 9443]:
            formatted_targets.append(f"https://{ip}:{port}")
        elif port in [80, 8080, 8000, 8888]:
            formatted_targets.append(f"http://{ip}:{port}")
        else:
            formatted_targets.append(f"{ip}:{port}")

    return list(dict.fromkeys(formatted_targets))


def _format_nuclei_targets_for_ip(ip: str, db: Optional[DatabaseManager]) -> List[str]:
    """Format an IP and its verified active services into Nuclei scan targets."""
    active_services = _get_verified_active_services_for_ip(ip, db)
    return _format_nuclei_targets_from_services(ip, active_services)


@router.post("/scan/nuclei")
async def start_nuclei_scan(
    req: NucleiScanRequest,
    request: Request,
    db: Optional[DatabaseManager] = Depends(get_db_manager),
) -> Dict:
    """Trigger asynchronous Nuclei vulnerability scan against marked targets/services."""
    runner = NucleiRunner()
    if not runner.is_available():
        raise HTTPException(
            status_code=503,
            detail="Nuclei binary not found on server. Ensure nuclei is installed in PATH.",
        )

    target_ips = req.targets if req.targets else list(_target_registry.keys())
    if not target_ips:
        raise HTTPException(status_code=400, detail="No IP targets selected or marked for Nuclei scan.")

    # Resolve active database
    active_db = db
    if not active_db or not Path(active_db.db_path).exists():
        current_db_path = getattr(request.app.state, "db_path", None)
        if current_db_path and Path(current_db_path).exists():
            active_db = DatabaseManager(Path(current_db_path))
            request.app.state.db_manager = active_db
        else:
            dbs_dir = Path.cwd() / "data" / "dbs"
            if dbs_dir.exists():
                existing_dbs = list(dbs_dir.glob("*.sqlite"))
                if existing_dbs:
                    active_db = DatabaseManager(existing_dbs[0])
                    request.app.state.db_manager = active_db
                    request.app.state.db_path = str(existing_dbs[0].resolve())

    async def _run_single_nuclei_scan(ip_to_scan: str):
        try:
            if ip_to_scan in _target_registry:
                _target_registry[ip_to_scan]["nuclei_status"] = "scanning"

            # Check if there are verified active services discovered by Masscan / active scan
            active_services = _get_verified_active_services_for_ip(ip_to_scan, active_db)

            if not active_services:
                # Query all mapped ports from passive sources (Shodan, Censys, etc.) for this IP
                existing_mapped_ports: List[int] = []
                if active_db and Path(active_db.db_path).exists():
                    import sqlite3
                    with sqlite3.connect(active_db.db_path) as conn:
                        ip_row = conn.execute("SELECT id FROM ip_addresses WHERE ip = ?", (ip_to_scan,)).fetchone()
                        if ip_row:
                            p_rows = conn.execute("SELECT DISTINCT port FROM services WHERE ip_id = ? AND port IS NOT NULL", (ip_row[0],)).fetchall()
                            existing_mapped_ports = [r[0] for r in p_rows if r[0]]

                # Build optimized port target: test specific mapped ports first if available
                if existing_mapped_ports:
                    ports_to_verify = f"-p{','.join(str(p) for p in sorted(set(existing_mapped_ports)))}"
                    _append_scan_log(
                        "info",
                        f"[Pre-Scan Rule] Verifying {len(existing_mapped_ports)} mapped passive port(s) ({ports_to_verify}) on {ip_to_scan} via Masscan...",
                        target=ip_to_scan
                    )
                else:
                    ports_to_verify = "--top-ports 100"
                    _append_scan_log(
                        "info",
                        f"[Pre-Scan Rule] No prior services mapped for {ip_to_scan}. Running Masscan Top 100 active port verification...",
                        target=ip_to_scan
                    )
                
                # Execute Masscan runner to verify active ports
                masscan_runner = MasscanRunner()
                if masscan_runner.is_available():
                    if ip_to_scan in _target_registry:
                        _target_registry[ip_to_scan]["status"] = "scanning"
                    
                    def _masscan_log_cb(lvl: str, m: str):
                        _append_scan_log(lvl, f"[Masscan Pre-Scan] {m}", target=ip_to_scan)

                    m_res = await masscan_runner.scan_target(
                        target=ip_to_scan,
                        ports=ports_to_verify,
                        rate=1000,
                        disable_ping=True,
                        banners=True,
                    )

                    if m_res.get("success"):
                        open_ports = m_res.get("ports", [])
                        if ip_to_scan in _target_registry:
                            _target_registry[ip_to_scan]["status"] = "completed"
                            _target_registry[ip_to_scan]["ports_count"] = len(open_ports)
                            _target_registry[ip_to_scan]["ports"] = open_ports
                            _target_registry[ip_to_scan]["last_scan"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                        if active_db and Path(active_db.db_path).exists() and open_ports:
                            active_db.merge_active_scan_services(ip_to_scan, open_ports)
                        
                        _append_scan_log(
                            "success",
                            f"[Masscan Pre-Scan] Verification completed for {ip_to_scan}: {len(open_ports)} active port(s) verified.",
                            target=ip_to_scan
                        )
                    else:
                        if ip_to_scan in _target_registry:
                            _target_registry[ip_to_scan]["status"] = "idle"
                        _append_scan_log(
                            "warning",
                            f"[Masscan Pre-Scan] Masscan verification returned no open ports or error: {m_res.get('error', 'No open ports')}",
                            target=ip_to_scan
                        )
                else:
                    _append_scan_log(
                        "warning",
                        f"[Pre-Scan Rule] Masscan binary not available to verify active ports for {ip_to_scan}.",
                        target=ip_to_scan
                    )

                # Re-query verified active services after Masscan execution
                active_services = _get_verified_active_services_for_ip(ip_to_scan, active_db)

            if not active_services:
                if ip_to_scan in _target_registry:
                    _target_registry[ip_to_scan]["nuclei_status"] = "completed"
                    _target_registry[ip_to_scan]["vulns_count"] = 0
                _append_scan_log(
                    "warning",
                    f"[Nuclei] Skipping Nuclei scan for {ip_to_scan}: No 'Verified Active' ports identified after pre-scan verification.",
                    target=ip_to_scan
                )
                return

            formatted_endpoints = _format_nuclei_targets_from_services(ip_to_scan, active_services)
            _append_scan_log(
                "info",
                f"[Nuclei] Dispatching scan on {ip_to_scan} ({len(formatted_endpoints)} verified active endpoint(s): {', '.join(formatted_endpoints[:3])})...",
                target=ip_to_scan
            )

            def _log_stream(level: str, msg: str):
                _append_scan_log(level, f"[Nuclei] {msg}", target=ip_to_scan)

            scan_res = await runner.scan_targets(
                targets=formatted_endpoints,
                severities=req.severities,
                tags=req.tags,
                custom_tags=req.custom_tags,
                rate_limit=req.rate_limit or 150,
                concurrency=req.concurrency or 25,
                custom_flags=req.custom_flags,
                timeout=600.0,
                log_callback=_log_stream,
            )

            if scan_res.get("success"):
                findings = scan_res.get("findings", [])
                if ip_to_scan in _target_registry:
                    _target_registry[ip_to_scan]["nuclei_status"] = "completed"
                    _target_registry[ip_to_scan]["vulns_count"] = len(findings)
                    _target_registry[ip_to_scan]["last_nuclei_scan"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                if active_db and Path(active_db.db_path).exists() and findings:
                    merge_info = active_db.merge_nuclei_findings(findings, fallback_ip=ip_to_scan)
                    _append_scan_log(
                        "success",
                        f"[Nuclei] Scan on {ip_to_scan} completed: {len(findings)} vulnerability issue(s) discovered. ({merge_info.get('added_vulnerabilities', 0)} new, {merge_info.get('updated_vulnerabilities', 0)} updated in graph).",
                        target=ip_to_scan
                    )
                else:
                    _append_scan_log(
                        "success",
                        f"[Nuclei] Scan on {ip_to_scan} completed. {len(findings)} vulnerability issue(s) identified.",
                        target=ip_to_scan
                    )
            else:
                err_msg = scan_res.get("error", "Unknown Nuclei execution error")
                if ip_to_scan in _target_registry:
                    _target_registry[ip_to_scan]["nuclei_status"] = "failed"
                _append_scan_log("error", f"[Nuclei] Scan on {ip_to_scan} failed: {err_msg}", target=ip_to_scan)

        except asyncio.CancelledError:
            if ip_to_scan in _target_registry:
                _target_registry[ip_to_scan]["nuclei_status"] = "idle"
            _append_scan_log("warning", f"[Nuclei] Scan on {ip_to_scan} cancelled.", target=ip_to_scan)
        except Exception as ex:
            if ip_to_scan in _target_registry:
                _target_registry[ip_to_scan]["nuclei_status"] = "failed"
            _append_scan_log("error", f"[Nuclei] Unexpected error scanning {ip_to_scan}: {str(ex)}", target=ip_to_scan)
        finally:
            _running_nuclei_tasks.pop(ip_to_scan, None)

    for ip in target_ips:
        if ip in _running_nuclei_tasks and not _running_nuclei_tasks[ip].done():
            _running_nuclei_tasks[ip].cancel()

        task = asyncio.create_task(_run_single_nuclei_scan(ip))
        _running_nuclei_tasks[ip] = task

    return {
        "success": True,
        "message": f"Nuclei vulnerability scan dispatched for {len(target_ips)} target(s).",
        "targets": target_ips,
        "severities": req.severities,
    }


@router.post("/scan/cancel")
async def cancel_active_scan(req: CancelScanRequest) -> Dict:
    """Cancel running active scan or Nuclei scan for a specific target or all targets."""
    cancelled = []
    scan_type = req.scan_type or "all"

    if req.all or not req.target:
        if scan_type in ["all", "masscan"]:
            for ip, task in list(_running_scan_tasks.items()):
                if not task.done():
                    task.cancel()
                    cancelled.append(f"masscan:{ip}")
                    if ip in _target_registry:
                        _target_registry[ip]["status"] = "idle"
            _running_scan_tasks.clear()

        if scan_type in ["all", "nuclei"]:
            for ip, task in list(_running_nuclei_tasks.items()):
                if not task.done():
                    task.cancel()
                    cancelled.append(f"nuclei:{ip}")
                    if ip in _target_registry:
                        _target_registry[ip]["nuclei_status"] = "idle"
            _running_nuclei_tasks.clear()

        _append_scan_log("info", "All running scans cancelled.")
    else:
        ip = req.target.strip()
        if scan_type in ["all", "masscan"] and ip in _running_scan_tasks:
            task = _running_scan_tasks[ip]
            if not task.done():
                task.cancel()
                cancelled.append(f"masscan:{ip}")
            _running_scan_tasks.pop(ip, None)
            if ip in _target_registry:
                _target_registry[ip]["status"] = "idle"
            _append_scan_log("info", f"Active port scan on {ip} cancelled.", target=ip)

        if scan_type in ["all", "nuclei"] and ip in _running_nuclei_tasks:
            task = _running_nuclei_tasks[ip]
            if not task.done():
                task.cancel()
                cancelled.append(f"nuclei:{ip}")
            _running_nuclei_tasks.pop(ip, None)
            if ip in _target_registry:
                _target_registry[ip]["nuclei_status"] = "idle"
            _append_scan_log("info", f"Nuclei scan on {ip} cancelled.", target=ip)

    return {
        "success": True,
        "cancelled_targets": cancelled,
    }


@router.get("/scan/status")
async def get_scan_status() -> Dict:
    """Get real-time scan status, target registry, and recent activity logs."""
    running_masscan = sum(1 for t in _target_registry.values() if t.get("status") == "scanning")
    running_nuclei = sum(1 for t in _target_registry.values() if t.get("nuclei_status") == "scanning")
    return {
        "running_scans": running_masscan + running_nuclei,
        "running_masscan": running_masscan,
        "running_nuclei": running_nuclei,
        "targets": list(_target_registry.values()),
        "total_targets": len(_target_registry),
        "recent_logs": _scan_log_history[-40:],
    }
