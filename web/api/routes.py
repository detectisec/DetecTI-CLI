"""REST API routes for DetecTI-CLI EASM dashboard."""

import asyncio
import ipaddress
import json
import socket
import sqlite3
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


class DeleteDbRequest(BaseModel):
    name: str


@router.get("/databases")
async def list_databases(request: Request) -> Dict:
    """List all available SQLite databases in ./data/dbs/ and return the currently active one."""
    data_dir = Path.cwd() / "data" / "dbs"
    databases = []
    
    current_db_path = getattr(request.app.state, "db_path", None)
    current_db_name = Path(current_db_path).name if current_db_path else None
    current_target_name = None
    
    if data_dir.exists():
        for db_file in sorted(data_dir.glob("*.sqlite")):
            size_mb = db_file.stat().st_size / (1024 * 1024)
            mod_time = datetime.fromtimestamp(db_file.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            
            clean_name = db_file.stem  # Strip .sqlite
            target = clean_name
            try:
                dm = DatabaseManager(db_file)
                stats = dm.get_summary_stats()
                if "target" in stats and stats["target"] and stats["target"] != "Unknown":
                    target = stats["target"]
            except Exception:
                pass
            
            is_curr = (db_file.name == current_db_name)
            if is_curr:
                current_target_name = target or clean_name
            
            databases.append({
                "filename": db_file.name,
                "name": clean_name,
                "clean_name": clean_name,
                "target": target,
                "display_name": target or clean_name,
                "size_mb": round(size_mb, 2),
                "modified": mod_time,
                "is_current": is_curr
            })
    
    return {
        "current_db": current_db_name,
        "current_target": current_target_name or (Path(current_db_path).stem if current_db_path else None),
        "databases": databases
    }


@router.post("/databases/select")
async def select_database(req: SelectDbRequest, request: Request) -> Dict:
    """Switch active SQLite database in the web dashboard."""
    dbs_dir = _get_dbs_dir()
    db_name = req.name.strip()
    if not db_name.endswith(".sqlite"):
        filename = f"{db_name}.sqlite"
    else:
        filename = db_name
        
    safe_filename = Path(filename).name
    db_file = dbs_dir / safe_filename
    if not db_file.exists():
        # Case-insensitive or matching by stem
        matches = [f for f in dbs_dir.glob("*.sqlite") if f.name.lower() == safe_filename.lower() or f.stem.lower() == db_name.lower()]
        if matches:
            db_file = matches[0]
            safe_filename = db_file.name
        else:
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
        "clean_name": db_file.stem,
        "db_path": str(db_file.resolve())
    }


def _get_dbs_dir() -> Path:
    base = Path.cwd() / "data" / "dbs"
    if base.exists():
        return base
    repo_base = Path(__file__).resolve().parent.parent.parent / "data" / "dbs"
    if repo_base.exists():
        return repo_base
    base.mkdir(parents=True, exist_ok=True)
    return base


async def _perform_delete_database(target_raw: str, request: Request) -> Dict:
    if not target_raw:
        raise HTTPException(status_code=400, detail="Database name is required")
    
    clean_target = target_raw.strip()
    if not clean_target.endswith(".sqlite"):
        filename = f"{clean_target}.sqlite"
    else:
        filename = clean_target
        
    safe_filename = Path(filename).name
    dbs_dir = _get_dbs_dir()
    db_file = dbs_dir / safe_filename
    
    if not db_file.exists():
        # Case-insensitive match or matching by stem
        matches = [f for f in dbs_dir.glob("*.sqlite") if f.name.lower() == safe_filename.lower() or f.stem.lower() == clean_target.lower()]
        if matches:
            db_file = matches[0]
            safe_filename = db_file.name
        else:
            raise HTTPException(status_code=404, detail=f"Database '{safe_filename}' not found in {dbs_dir}")
    
    try:
        if db_file.exists():
            db_file.unlink()
        wal_file = db_file.with_name(f"{db_file.name}-wal")
        if wal_file.exists():
            wal_file.unlink()
        shm_file = db_file.with_name(f"{db_file.name}-shm")
        if shm_file.exists():
            shm_file.unlink()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete database: {exc}")
    
    # Check if this was the active database
    current_db_path = getattr(request.app.state, "db_path", None)
    was_current = False
    new_active_db = None
    if current_db_path and Path(current_db_path).resolve() == db_file.resolve():
        was_current = True
        remaining_dbs = sorted(dbs_dir.glob("*.sqlite"))
        if remaining_dbs:
            new_db_file = remaining_dbs[0]
            request.app.state.db_manager = DatabaseManager(new_db_file)
            request.app.state.db_path = str(new_db_file.resolve())
            new_active_db = new_db_file.name
        else:
            request.app.state.db_manager = None
            request.app.state.db_path = None
    
    return {
        "success": True,
        "deleted": safe_filename,
        "clean_name": safe_filename[:-7] if safe_filename.endswith(".sqlite") else safe_filename,
        "was_current": was_current,
        "new_active_db": new_active_db
    }


@router.post("/databases/delete")
async def delete_database_post(req: DeleteDbRequest, request: Request) -> Dict:
    """Delete a SQLite database file via JSON POST body."""
    return await _perform_delete_database(req.name, request)


@router.delete("/databases/{db_name}")
async def delete_database_by_param(db_name: str, request: Request) -> Dict:
    """Delete a SQLite database file via URL path parameter."""
    return await _perform_delete_database(db_name, request)


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
            "verified_services": 0,
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
            "verified_services": stats.get("verified_services", 0),
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

from modules.masscan import (
    MasscanRunner,
    build_port_ranges_excluding,
    filter_ports_excluding,
    parse_port_spec_to_set,
)
from modules.nuclei import NucleiRunner

# In-memory target registry and running tasks tracking
_target_registry: Dict[str, Dict] = {}
_running_scan_tasks: Dict[str, asyncio.Task] = {}
_running_nuclei_tasks: Dict[str, asyncio.Task] = {}
_scan_log_history: List[Dict] = []


def _get_target_ports_partition(target: str, db: Optional[DatabaseManager]) -> tuple[set[int], set[int]]:
    """Retrieve verified active ports and unverified passive ports for an IP or FQDN/Domain/Subdomain from database.
    
    Returns:
        (verified_ports_set, unverified_passive_ports_set)
    """
    verified_ports: set[int] = set()
    unverified_passive_ports: set[int] = set()
    if db and Path(db.db_path).exists():
        with sqlite3.connect(db.db_path) as conn:
            is_ip = False
            try:
                ipaddress.ip_address(target)
                is_ip = True
            except ValueError:
                is_ip = False

            ip_ids = []
            if is_ip:
                ip_row = conn.execute("SELECT id FROM ip_addresses WHERE ip = ?", (target,)).fetchone()
                if ip_row:
                    ip_ids = [ip_row[0]]
            else:
                cursor = conn.execute("""
                    SELECT ip_id FROM subdomain_ips 
                    JOIN subdomains ON subdomains.id = subdomain_ips.subdomain_id
                    WHERE LOWER(subdomains.name) = LOWER(?)
                """, (target,))
                ip_ids = [r[0] for r in cursor.fetchall()]
                if not ip_ids:
                    cursor = conn.execute("""
                        SELECT ip_id FROM subdomain_ips
                        JOIN subdomains ON subdomains.id = subdomain_ips.subdomain_id
                        JOIN domains ON domains.id = subdomains.domain_id
                        WHERE LOWER(domains.name) = LOWER(?)
                    """, (target,))
                    ip_ids = [r[0] for r in cursor.fetchall()]

            for ip_id in ip_ids:
                services = conn.execute("SELECT port, sources FROM services WHERE ip_id = ?", (ip_id,)).fetchall()
                for p_num, s_sources in services:
                    try:
                        p_val = int(p_num)
                    except (ValueError, TypeError):
                        continue
                    sources_list = []
                    if s_sources:
                        try:
                            sources_list = json.loads(s_sources)
                            if not isinstance(sources_list, list):
                                sources_list = [str(sources_list)]
                        except Exception:
                            sources_list = [s_sources]

                    is_verified = any(
                        isinstance(s, str) and ("masscan" in s.lower() or "active" in s.lower() or "nuclei" in s.lower())
                        for s in sources_list
                    )
                    if is_verified:
                        verified_ports.add(p_val)
                    else:
                        unverified_passive_ports.add(p_val)
    return verified_ports, unverified_passive_ports


class TargetActionRequest(BaseModel):
    ip: Optional[str] = None
    target: Optional[str] = None

    @property
    def target_val(self) -> str:
        return (self.target or self.ip or "").strip()


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


class UnverifyServicesRequest(BaseModel):
    service_ids: Optional[List[str]] = None
    ip_addresses: Optional[List[str]] = None
    all_services: Optional[bool] = False


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
    """List all currently marked targets (IPs and FQDNs) with their scan statuses."""
    return {
        "targets": list(_target_registry.values()),
        "count": len(_target_registry),
    }


@router.post("/targets/set")
async def set_target(req: TargetActionRequest) -> Dict:
    """Mark an IP or FQDN/Domain/Subdomain as an active target."""
    target = req.target_val
    if not target:
        raise HTTPException(status_code=400, detail="Invalid target address or hostname")
    
    target_type = "ip"
    try:
        ipaddress.ip_address(target)
    except ValueError:
        target_type = "fqdn"

    if target not in _target_registry:
        _target_registry[target] = {
            "ip": target,
            "target_type": target_type,
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
        _append_scan_log("info", f"Target {target} ({target_type.upper()}) added to active targets.", target=target)
    
    return {
        "success": True,
        "target": _target_registry[target],
        "total_targets": len(_target_registry),
    }


@router.post("/targets/remove")
async def remove_target(req: TargetActionRequest) -> Dict:
    """Remove a target from the marked targets list."""
    target = req.target_val
    if target in _running_scan_tasks:
        task = _running_scan_tasks[target]
        if not task.done():
            task.cancel()
        _running_scan_tasks.pop(target, None)

    if target in _running_nuclei_tasks:
        task = _running_nuclei_tasks[target]
        if not task.done():
            task.cancel()
        _running_nuclei_tasks.pop(target, None)

    if target in _target_registry:
        del _target_registry[target]
        _append_scan_log("info", f"Target {target} removed from targets.", target=target)
    
    return {
        "success": True,
        "removed": target,
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


def _resolve_db_manager(request: Request, db: Optional[DatabaseManager] = None, target: Optional[str] = None) -> Optional[DatabaseManager]:
    if db and Path(db.db_path).exists():
        return db
    app_db = getattr(request.app.state, "db_manager", None)
    if app_db and Path(app_db.db_path).exists():
        return app_db
    if target:
        cand = Path.cwd() / "data" / "dbs" / f"{target}.sqlite"
        if cand.exists():
            return DatabaseManager(cand)
        cand_raw = Path.cwd() / "data" / "dbs" / target
        if cand_raw.exists():
            return DatabaseManager(cand_raw)
    dbs_dir = Path.cwd() / "data" / "dbs"
    if dbs_dir.exists():
        dbs = sorted(list(dbs_dir.glob("*.sqlite")))
        if dbs:
            return DatabaseManager(dbs[0])
    return None


@router.post("/services/unverify")
async def unverify_services_endpoint(
    req: UnverifyServicesRequest,
    request: Request,
    target: Optional[str] = Query(None, description="Active target name"),
    db: Optional[DatabaseManager] = Depends(get_db_manager),
) -> Dict:
    """Remove active verification status (Masscan source) from specified services, IPs, or root nodes.
    
    Allows analysts to reset services back to passive state for targeted re-validation without losing assets.
    """
    active_db = _resolve_db_manager(request, db, target)
    if not active_db or not Path(active_db.db_path).exists():
        raise HTTPException(status_code=404, detail="No active scan database found")

    res = active_db.unverify_services(
        service_ids=req.service_ids,
        ip_addresses=req.ip_addresses,
        all_services=bool(req.all_services)
    )

    # Synchronize in-memory target registry ports count
    for ip, t_info in _target_registry.items():
        v_ports, _ = _get_target_ports_partition(ip, active_db)
        t_info["ports_count"] = len(v_ports)

    # Log to live console
    target_label = target or "Active Target"
    _append_scan_log(
        "info",
        f"[Service Reset] Removed 'Confirmed Active' status from {res.get('unverified_count', 0)} service(s) to allow fresh re-validation.",
        target=target_label
    )

    return res


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

            # Resolve active DB
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

            # Resolve target to IP if FQDN
            scan_ip = ip_to_scan
            try:
                ipaddress.ip_address(ip_to_scan)
            except ValueError:
                resolved_ip = None
                try:
                    addr_info = socket.getaddrinfo(ip_to_scan, None, socket.AF_UNSPEC)
                    if addr_info:
                        resolved_ip = addr_info[0][4][0]
                except Exception:
                    pass

                if active_db and Path(active_db.db_path).exists():
                    with sqlite3.connect(active_db.db_path) as conn:
                        if not resolved_ip:
                            row = conn.execute("""
                                SELECT ip_addresses.ip FROM ip_addresses
                                JOIN subdomain_ips ON subdomain_ips.ip_id = ip_addresses.id
                                JOIN subdomains ON subdomains.id = subdomain_ips.subdomain_id
                                WHERE LOWER(subdomains.name) = LOWER(?)
                            """, (ip_to_scan,)).fetchone()
                            if row:
                                resolved_ip = row[0]
                        
                        # If resolved via DNS, immediately persist and bind in database
                        if resolved_ip:
                            # 1. Ensure subdomain node exists
                            sub_row = conn.execute("SELECT id FROM subdomains WHERE LOWER(name) = LOWER(?)", (ip_to_scan,)).fetchone()
                            if sub_row:
                                sub_id = sub_row[0]
                            else:
                                dom_id = None
                                for d_id, d_name in conn.execute("SELECT id, name FROM domains").fetchall():
                                    d_clean = d_name.lower().strip()
                                    if ip_to_scan.lower() == d_clean or ip_to_scan.lower().endswith(f".{d_clean}"):
                                        dom_id = d_id
                                        break
                                if not dom_id:
                                    dom_id = str(uuid.uuid4())
                                    conn.execute("INSERT OR IGNORE INTO domains (id, name) VALUES (?, ?)", (dom_id, ip_to_scan))
                                    d_fetch = conn.execute("SELECT id FROM domains WHERE LOWER(name) = LOWER(?)", (ip_to_scan,)).fetchone()
                                    if d_fetch:
                                        dom_id = d_fetch[0]

                                sub_id = str(uuid.uuid4())
                                conn.execute("INSERT OR IGNORE INTO subdomains (id, domain_id, name) VALUES (?, ?, ?)", (sub_id, dom_id, ip_to_scan))
                                s_fetch = conn.execute("SELECT id FROM subdomains WHERE LOWER(name) = LOWER(?)", (ip_to_scan,)).fetchone()
                                if s_fetch:
                                    sub_id = s_fetch[0]

                            # 2. Ensure IP exists
                            ip_row = conn.execute("SELECT id FROM ip_addresses WHERE ip = ?", (resolved_ip,)).fetchone()
                            if ip_row:
                                cur_ip_id = ip_row[0]
                            else:
                                cur_ip_id = str(uuid.uuid4())
                                conn.execute("""
                                    INSERT INTO ip_addresses (id, ip, org, country, asn)
                                    VALUES (?, ?, ?, ?, ?)
                                """, (cur_ip_id, resolved_ip, "Active Target", "Unknown", "Unknown"))

                            # 3. Ensure direct RESOLVES_TO link in subdomain_ips
                            conn.execute("""
                                INSERT OR IGNORE INTO subdomain_ips (subdomain_id, ip_id)
                                VALUES (?, ?)
                            """, (sub_id, cur_ip_id))
                            conn.commit()

                if resolved_ip:
                    scan_ip = resolved_ip
                    _append_scan_log("info", f"[Masscan] Target FQDN '{ip_to_scan}' resolved to IP {scan_ip} (persisted & linked in graph).", target=ip_to_scan)

            # 1. Inspect existing ports for target in database
            verified_ports, unverified_passive_ports = _get_target_ports_partition(ip_to_scan, active_db)

            # Check if this is an "All Ports" (0-65535) scan
            clean_ports_arg = (ports_arg or "").strip().lower()
            if clean_ports_arg.startswith("-p"):
                clean_ports_arg = clean_ports_arg[2:].strip()
            is_all_ports = clean_ports_arg in ("-", "all", "0-65535", "1-65535", "-p0-65535", "-p1-65535")

            accumulated_open_ports = []

            if is_all_ports:
                # -------------------------------------------------------------
                # 2-PHASE PIPELINE FOR ALL PORTS (0-65535)
                # -------------------------------------------------------------
                # Phase 1: High-Priority Scan on Passive Unverified Ports
                phase1_ports = unverified_passive_ports - verified_ports
                if phase1_ports:
                    p1_spec = ",".join(str(p) for p in sorted(phase1_ports))
                    _append_scan_log(
                        "info",
                        f"[Masscan Phase 1 (Priority)] Found {len(phase1_ports)} unverified passive port(s) [{p1_spec}] on {ip_to_scan}. Scanning immediately for fast active confirmation...",
                        target=ip_to_scan
                    )
                    p1_res = await runner.scan_target(
                        target_ip=scan_ip,
                        ports=p1_spec,
                        rate=rate_arg,
                        disable_ping=pn_arg,
                        banners=banners_arg,
                        custom_flags=flags_arg,
                        timeout=60.0,
                    )
                    p1_found = p1_res.get("ports") or p1_res.get("open_ports") or []
                    if p1_found:
                        accumulated_open_ports.extend(p1_found)
                        if active_db and Path(active_db.db_path).exists():
                            m_info = active_db.merge_active_scan_services(ip_to_scan, p1_found)
                            _append_scan_log(
                                "success",
                                f"[Masscan Phase 1 Complete] Verified {len(p1_found)} port(s) on {ip_to_scan} ({m_info.get('added_services', 0)} new, {m_info.get('updated_services', 0)} confirmed active).",
                                target=ip_to_scan
                            )
                        # Re-partition verified ports
                        verified_ports, unverified_passive_ports = _get_target_ports_partition(ip_to_scan, active_db)
                else:
                    _append_scan_log(
                        "info",
                        f"[Masscan Phase 1 Skip] No unverified passive ports awaiting priority confirmation on {ip_to_scan}. Skipping Phase 1 and advancing to full range sweep.",
                        target=ip_to_scan
                    )

                # Phase 2: Sweep remaining ports of the 0-65535 range
                all_excluded = verified_ports | phase1_ports
                p2_spec = build_port_ranges_excluding(0, 65535, all_excluded)
                remaining_ports_count = max(0, 65536 - len(all_excluded))

                if remaining_ports_count == 0:
                    _append_scan_log(
                        "info",
                        f"[Masscan Phase 2 Skip] All 65,536 ports on {ip_to_scan} have already been tested or confirmed active in database. Skipping Phase 2 sweep.",
                        target=ip_to_scan
                    )
                else:
                    ex_summary = ", ".join(str(p) for p in sorted(all_excluded)[:10]) + ("..." if len(all_excluded) > 10 else "")
                    _append_scan_log(
                        "info",
                        f"[Masscan Phase 2 (Sweep)] Sweeping remaining {remaining_ports_count:,} ports on {ip_to_scan} (excluding {len(all_excluded)} already-tested/confirmed ports: [{ex_summary}] to avoid redundant network load)...",
                        target=ip_to_scan
                    )

                    p2_res = await runner.scan_target(
                        target_ip=scan_ip,
                        ports=p2_spec,
                        rate=rate_arg,
                        disable_ping=pn_arg,
                        banners=banners_arg,
                        custom_flags=flags_arg,
                        timeout=180.0,
                    )

                    p2_found = p2_res.get("ports") or p2_res.get("open_ports") or []
                    if p2_found:
                        accumulated_open_ports.extend(p2_found)
                        if active_db and Path(active_db.db_path).exists():
                            m_info = active_db.merge_active_scan_services(ip_to_scan, p2_found)
                            _append_scan_log(
                                "success",
                                f"[Masscan Phase 2] Discovered {len(p2_found)} additional open port(s) on {ip_to_scan}.",
                                target=ip_to_scan
                            )

                # Deduplicate accumulated open ports by port and proto
                unique_ports = {}
                for p in accumulated_open_ports:
                    k = (p.get("port"), (p.get("protocol") or "tcp").lower())
                    unique_ports[k] = p
                final_open_ports = list(unique_ports.values())

                is_success = (len(final_open_ports) > 0) or (remaining_ports_count == 0) or p2_res.get("success", False)
                if is_success:
                    _target_registry[ip_to_scan]["status"] = "completed"
                    _target_registry[ip_to_scan]["ports_count"] = len(final_open_ports)
                    _target_registry[ip_to_scan]["ports"] = final_open_ports
                    _target_registry[ip_to_scan]["last_scan"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    _append_scan_log(
                        "success",
                        f"[Masscan Full Sweep Complete] Scan on {ip_to_scan} completed: {len(final_open_ports)} total verified active port(s).",
                        target=ip_to_scan
                    )
                else:
                    err_msg = p2_res.get("error", "Scan finished without open ports")
                    _target_registry[ip_to_scan]["status"] = "completed" if len(final_open_ports) > 0 else "failed"
                    _target_registry[ip_to_scan]["ports_count"] = len(final_open_ports)
                    _target_registry[ip_to_scan]["ports"] = final_open_ports
                    _target_registry[ip_to_scan]["error"] = err_msg if not final_open_ports else None
                    _append_scan_log(
                        "warning" if final_open_ports else "error",
                        f"[Masscan] Sweep on {ip_to_scan} ended: {err_msg} ({len(final_open_ports)} ports preserved).",
                        target=ip_to_scan
                    )

            else:
                # -------------------------------------------------------------
                # STANDARD SCAN WITH SMART VERIFIED PORT EXCLUSION
                # -------------------------------------------------------------
                filtered_ports, remaining_count, excluded_count, actual_ex = filter_ports_excluding(ports_arg, verified_ports)
                
                if not filtered_ports or remaining_count == 0:
                    ex_list_str = ", ".join(str(p) for p in sorted(actual_ex)[:15]) + ("..." if len(actual_ex) > 15 else "")
                    _target_registry[ip_to_scan]["status"] = "completed"
                    _target_registry[ip_to_scan]["ports_count"] = len(verified_ports)
                    _target_registry[ip_to_scan]["last_scan"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    _append_scan_log(
                        "success",
                        f"[Masscan Smart Skip] Scan skipped on {ip_to_scan}: 100% of requested ports [{ports_arg}] ({len(actual_ex)} port(s): [{ex_list_str}]) are already verified as Confirmed Active in database. Redundant probing skipped to reduce target load.",
                        target=ip_to_scan
                    )
                    return

                if excluded_count > 0:
                    ex_list_str = ", ".join(str(p) for p in sorted(actual_ex)[:10]) + ("..." if len(actual_ex) > 10 else "")
                    _append_scan_log(
                        "info",
                        f"[Masscan Smart Filter] Excluded {excluded_count} port(s) [{ex_list_str}] because they are already Confirmed Active. Scanning {remaining_count} remaining unverified port(s) on {ip_to_scan} ({filtered_ports}, {rate_arg} pps)...",
                        target=ip_to_scan
                    )
                else:
                    _append_scan_log(
                        "info",
                        f"Starting active scan on {ip_to_scan} ({filtered_ports}, {rate_arg} pps)...",
                        target=ip_to_scan
                    )

                scan_res = await runner.scan_target(
                    target_ip=scan_ip,
                    ports=filtered_ports,
                    rate=rate_arg,
                    disable_ping=pn_arg,
                    banners=banners_arg,
                    custom_flags=flags_arg,
                    timeout=180.0,
                )

                open_ports = scan_res.get("ports") or scan_res.get("open_ports") or []
                if open_ports and active_db and Path(active_db.db_path).exists():
                    merge_info = active_db.merge_active_scan_services(ip_to_scan, open_ports)
                    _append_scan_log(
                        "success",
                        f"Persisted {len(open_ports)} verified port(s) to database ({merge_info.get('added_services', 0)} new, {merge_info.get('updated_services', 0)} verified).",
                        target=ip_to_scan,
                    )

                # Re-query total verified ports count
                v_ports, _ = _get_target_ports_partition(ip_to_scan, active_db)
                total_verified_count = len(v_ports) if v_ports else len(open_ports)

                if scan_res.get("success") or open_ports:
                    _target_registry[ip_to_scan]["status"] = "completed"
                    _target_registry[ip_to_scan]["ports_count"] = total_verified_count
                    _target_registry[ip_to_scan]["ports"] = open_ports
                    _target_registry[ip_to_scan]["last_scan"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    _append_scan_log(
                        "success",
                        f"Scan on {ip_to_scan} completed: {len(open_ports)} open port(s) newly verified ({total_verified_count} total active).",
                        target=ip_to_scan
                    )
                else:
                    err_msg = scan_res.get("error", "Unknown scan error")
                    _target_registry[ip_to_scan]["status"] = "failed"
                    _target_registry[ip_to_scan]["ports_count"] = total_verified_count
                    _target_registry[ip_to_scan]["ports"] = open_ports
                    _target_registry[ip_to_scan]["error"] = err_msg
                    _append_scan_log(
                        "warning" if open_ports else "error",
                        f"Scan on {ip_to_scan} ended with warning/timeout: {err_msg} ({total_verified_count} ports preserved).",
                        target=ip_to_scan
                    )

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
def _get_verified_active_services_for_target(target: str, db: Optional[DatabaseManager]) -> List[Dict[str, Any]]:
    """Retrieve all verified active services for an IP or FQDN/Domain/Subdomain from database."""
    active_services = []
    if db and Path(db.db_path).exists():
        with sqlite3.connect(db.db_path) as conn:
            is_ip = False
            try:
                ipaddress.ip_address(target)
                is_ip = True
            except ValueError:
                is_ip = False

            ip_ids = []
            if is_ip:
                ip_row = conn.execute("SELECT id FROM ip_addresses WHERE ip = ?", (target,)).fetchone()
                if ip_row:
                    ip_ids = [ip_row[0]]
            else:
                cursor = conn.execute("""
                    SELECT ip_id FROM subdomain_ips 
                    JOIN subdomains ON subdomains.id = subdomain_ips.subdomain_id
                    WHERE LOWER(subdomains.name) = LOWER(?)
                """, (target,))
                ip_ids = [r[0] for r in cursor.fetchall()]
                if not ip_ids:
                    cursor = conn.execute("""
                        SELECT ip_id FROM subdomain_ips
                        JOIN subdomains ON subdomains.id = subdomain_ips.subdomain_id
                        JOIN domains ON domains.id = subdomains.domain_id
                        WHERE LOWER(domains.name) = LOWER(?)
                    """, (target,))
                    ip_ids = [r[0] for r in cursor.fetchall()]

            for ip_id in ip_ids:
                services = conn.execute(
                    "SELECT port, protocol, service_name, url, ssl, sources, banner FROM services WHERE ip_id = ?",
                    (ip_id,)
                ).fetchall()
                for port, proto, s_name, s_url, s_ssl, s_sources, s_banner in services:
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
                    )

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


def _get_verified_active_services_for_ip(ip: str, db: Optional[DatabaseManager]) -> List[Dict[str, Any]]:
    return _get_verified_active_services_for_target(ip, db)


def _format_nuclei_targets_from_services(target: str, services: List[Dict[str, Any]]) -> List[str]:
    """Format verified active services or FQDN into Nuclei endpoint URLs/host-ports."""
    formatted_targets: List[str] = []
    if target.startswith("http://") or target.startswith("https://"):
        formatted_targets.append(target.strip())

    for svc in services:
        port = svc["port"]
        s_url = svc.get("url")
        s_ssl = svc.get("ssl", False)
        if s_url and str(s_url).startswith("http"):
            formatted_targets.append(str(s_url).strip())
        elif s_ssl or port in [443, 8443, 9443]:
            formatted_targets.append(f"https://{target}:{port}")
        elif port in [80, 8080, 8000, 8888]:
            formatted_targets.append(f"http://{target}:{port}")
        else:
            formatted_targets.append(f"{target}:{port}")

    # Fallback for FQDNs / URLs if no explicit ports are mapped
    if not formatted_targets and not target.startswith("http"):
        try:
            ipaddress.ip_address(target)
        except ValueError:
            formatted_targets = [f"https://{target}", f"http://{target}"]

    return list(dict.fromkeys(formatted_targets))


def _format_nuclei_targets_for_ip(ip: str, db: Optional[DatabaseManager]) -> List[str]:
    """Format a target and its verified active services into Nuclei scan targets."""
    active_services = _get_verified_active_services_for_target(ip, db)
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
        raise HTTPException(status_code=400, detail="No targets selected or marked for Nuclei scan.")

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

    async def _run_single_nuclei_scan(target_to_scan: str):
        try:
            if target_to_scan in _target_registry:
                _target_registry[target_to_scan]["nuclei_status"] = "scanning"

            is_ip = False
            try:
                ipaddress.ip_address(target_to_scan)
                is_ip = True
            except ValueError:
                is_ip = False

            # 1. Check if there are already verified active services discovered by Masscan / active scan
            active_services = _get_verified_active_services_for_target(target_to_scan, active_db)

            if not active_services:
                if not is_ip:
                    # FQDN target behind CDN/Reverse Proxy -> Scan web endpoints directly with Nuclei
                    formatted_endpoints = _format_nuclei_targets_from_services(target_to_scan, [])
                    _append_scan_log(
                        "info",
                        f"[Nuclei] FQDN target {target_to_scan} (Reverse Proxy / Virtual Host). Dispatching web scan directly against {', '.join(formatted_endpoints)}...",
                        target=target_to_scan
                    )
                else:
                    # 2. Check if IP target has unverified passive ports mapped in database
                    verified_ports, unverified_passive_ports = _get_target_ports_partition(target_to_scan, active_db)

                    if not unverified_passive_ports:
                        if target_to_scan in _target_registry:
                            _target_registry[target_to_scan]["nuclei_status"] = "completed"
                            _target_registry[target_to_scan]["vulns_count"] = 0
                        _append_scan_log(
                            "warning",
                            f"[Nuclei Smart Skip] Skipped vulnerability scan on {target_to_scan}: IP has no 'Confirmed Active' services and 0 mapped passive ports in database. Run a Masscan port scan first or add services to enable Nuclei scanning.",
                            target=target_to_scan
                        )
                        return

                    # Target has unverified passive ports -> Request Masscan verification strictly on these passive ports
                    ports_to_verify = ",".join(str(p) for p in sorted(unverified_passive_ports))
                    _append_scan_log(
                        "info",
                        f"[Nuclei Pre-Scan] Target {target_to_scan} has {len(unverified_passive_ports)} unverified passive port(s) [{ports_to_verify}]. Requesting Masscan verification strictly on these ports before Nuclei execution...",
                        target=target_to_scan
                    )

                    masscan_runner = MasscanRunner()
                    if masscan_runner.is_available():
                        if target_to_scan in _target_registry:
                            _target_registry[target_to_scan]["status"] = "scanning"

                        m_res = await masscan_runner.scan_target(
                            target_ip=target_to_scan,
                            ports=ports_to_verify,
                            rate=1000,
                            disable_ping=True,
                            banners=True,
                        )

                        open_ports = m_res.get("ports") or m_res.get("open_ports") or []
                        if open_ports:
                            if target_to_scan in _target_registry:
                                _target_registry[target_to_scan]["status"] = "completed"
                                _target_registry[target_to_scan]["ports_count"] = len(open_ports)
                                _target_registry[target_to_scan]["ports"] = open_ports
                                _target_registry[target_to_scan]["last_scan"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                            if active_db and Path(active_db.db_path).exists():
                                active_db.merge_active_scan_services(target_to_scan, open_ports)
                            
                            _append_scan_log(
                                "success",
                                f"[Nuclei Pre-Scan] Masscan verified {len(open_ports)} of {len(unverified_passive_ports)} passive port(s) as Confirmed Active on {target_to_scan}. Proceeding with Nuclei vulnerability scan.",
                                target=target_to_scan
                            )
                        else:
                            if target_to_scan in _target_registry:
                                _target_registry[target_to_scan]["status"] = "completed"
                            _append_scan_log(
                                "warning",
                                f"[Nuclei Pre-Scan] Masscan verification returned 0 open ports for passive ports [{ports_to_verify}] on {target_to_scan}.",
                                target=target_to_scan
                            )
                    else:
                        _append_scan_log(
                            "warning",
                            f"[Nuclei Pre-Scan] Masscan binary not available to verify passive ports [{ports_to_verify}] on {target_to_scan}.",
                            target=target_to_scan
                        )

                    # Re-query verified active services after Masscan execution
                    active_services = _get_verified_active_services_for_target(target_to_scan, active_db)

                    if not active_services:
                        if target_to_scan in _target_registry:
                            _target_registry[target_to_scan]["nuclei_status"] = "completed"
                            _target_registry[target_to_scan]["vulns_count"] = 0
                        _append_scan_log(
                            "warning",
                            f"[Nuclei Smart Skip] Skipped vulnerability scan on {target_to_scan}: None of the target's passive ports responded as 'Confirmed Active' during Masscan verification.",
                            target=target_to_scan
                        )
                        return

                    formatted_endpoints = _format_nuclei_targets_from_services(target_to_scan, active_services)
            else:
                formatted_endpoints = _format_nuclei_targets_from_services(target_to_scan, active_services)

            _append_scan_log(
                "info",
                f"[Nuclei] Dispatching scan on {target_to_scan} ({len(formatted_endpoints)} endpoint(s): {', '.join(formatted_endpoints[:3])})...",
                target=target_to_scan
            )

            def _log_stream(level: str, msg: str):
                _append_scan_log(level, f"[Nuclei] {msg}", target=target_to_scan)

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
                if target_to_scan in _target_registry:
                    _target_registry[target_to_scan]["nuclei_status"] = "completed"
                    _target_registry[target_to_scan]["vulns_count"] = len(findings)
                    _target_registry[target_to_scan]["last_nuclei_scan"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                if active_db and Path(active_db.db_path).exists() and findings:
                    merge_info = active_db.merge_nuclei_findings(findings, fallback_ip=target_to_scan)
                    _append_scan_log(
                        "success",
                        f"[Nuclei] Scan on {target_to_scan} completed: {len(findings)} vulnerability issue(s) discovered. ({merge_info.get('added_vulnerabilities', 0)} new, {merge_info.get('updated_vulnerabilities', 0)} updated in graph).",
                        target=target_to_scan
                    )
                else:
                    _append_scan_log(
                        "success",
                        f"[Nuclei] Scan on {target_to_scan} completed. {len(findings)} vulnerability issue(s) identified.",
                        target=target_to_scan
                    )
            else:
                err_msg = scan_res.get("error", "Unknown Nuclei execution error")
                if target_to_scan in _target_registry:
                    _target_registry[target_to_scan]["nuclei_status"] = "failed"
                _append_scan_log("error", f"[Nuclei] Scan on {target_to_scan} failed: {err_msg}", target=target_to_scan)

        except asyncio.CancelledError:
            if target_to_scan in _target_registry:
                _target_registry[target_to_scan]["nuclei_status"] = "idle"
            _append_scan_log("warning", f"[Nuclei] Scan on {target_to_scan} cancelled.", target=target_to_scan)
        except Exception as ex:
            if target_to_scan in _target_registry:
                _target_registry[target_to_scan]["nuclei_status"] = "failed"
            _append_scan_log("error", f"[Nuclei] Unexpected error scanning {target_to_scan}: {str(ex)}", target=target_to_scan)
        finally:
            _running_nuclei_tasks.pop(target_to_scan, None)

    # Ensure Nuclei community templates are updated safely (once with mutex lock + cooldown)
    if runner.is_available():
        def _tpl_log(lvl: str, m: str):
            _append_scan_log(lvl, f"[Nuclei Engine] {m}")
        await runner.update_templates(cooldown_seconds=3600.0, log_callback=_tpl_log)

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
