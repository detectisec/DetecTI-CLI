"""Nuclei vulnerability scanner runner module."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("detecti.nuclei")


class NucleiRunner:
    """Async Nuclei execution engine for vulnerability scanning."""

    _update_lock: asyncio.Lock = asyncio.Lock()
    _last_templates_update: float = 0.0

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = binary_path or shutil.which("nuclei") or "/usr/bin/nuclei"

    def is_available(self) -> bool:
        """Check if nuclei binary exists and is executable."""
        if not self.binary_path:
            return False
        p = Path(self.binary_path)
        return p.exists() and os.access(str(p), os.X_OK)

    def check_permissions(self) -> Dict[str, Any]:
        """Verify binary availability."""
        available = self.is_available()
        return {
            "available": available,
            "binary_path": self.binary_path if available else None,
            "can_run": available,
            "message": (
                "Nuclei engine ready"
                if available
                else "Nuclei binary not found on system (install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest or download from GitHub releases)"
            ),
        }

    async def update_templates(
        self,
        force: bool = False,
        cooldown_seconds: float = 3600.0,
        log_callback: Optional[Callable[[str, str], Any]] = None,
    ) -> Dict[str, Any]:
        """Update nuclei-templates to the latest release safely with lock and cooldown."""
        if not self.is_available():
            return {"success": False, "error": "Nuclei binary not found"}

        import time
        now = time.time()
        
        async with NucleiRunner._update_lock:
            # Check if updated recently unless forced
            if not force and (now - NucleiRunner._last_templates_update) < cooldown_seconds:
                msg = "Nuclei templates are already up to date (cached within cooldown)."
                logger.info(msg)
                if log_callback:
                    log_callback("info", msg)
                return {"success": True, "updated": False, "message": msg}

            logger.info("Executing Nuclei templates update (-update-templates)...")
            if log_callback:
                log_callback("info", "Checking and updating Nuclei community templates...")

            try:
                cmd = [self.binary_path, "-update-templates", "-duc"]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=60.0)
                out_str = stdout_bytes.decode("utf-8", errors="replace") + stderr_bytes.decode("utf-8", errors="replace")
                
                NucleiRunner._last_templates_update = time.time()
                success = (proc.returncode == 0)
                
                log_msg = f"Nuclei templates update finished: {out_str.strip().splitlines()[-1] if out_str.strip() else 'OK'}"
                logger.info(log_msg)
                if log_callback:
                    log_callback("success" if success else "warning", log_msg)

                return {
                    "success": success,
                    "updated": True,
                    "output": out_str.strip(),
                }
            except asyncio.TimeoutError:
                msg = "Nuclei templates update timed out after 60s (proceeding with existing templates)."
                logger.warning(msg)
                if log_callback:
                    log_callback("warning", msg)
                return {"success": False, "error": msg}
            except Exception as e:
                msg = f"Error updating Nuclei templates: {e}"
                logger.warning(msg)
                if log_callback:
                    log_callback("warning", msg)
                return {"success": False, "error": msg}

    async def scan_targets(
        self,
        targets: List[str],
        severities: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        custom_tags: Optional[str] = None,
        rate_limit: int = 150,
        concurrency: int = 25,
        custom_flags: Optional[str] = None,
        timeout: float = 600.0,
        log_callback: Optional[Callable[[str, str], Any]] = None,
    ) -> Dict[str, Any]:
        """Execute nuclei against a list of formatted targets with real-time JSONL parsing."""
        if not self.is_available():
            return {
                "success": False,
                "targets": targets,
                "findings": [],
                "error": "Nuclei binary is not available on this system.",
            }

        if not targets:
            return {
                "success": True,
                "targets": [],
                "findings": [],
                "error": None,
                "total_findings": 0,
            }

        # Normalize severities
        sev_list = [s.strip().lower() for s in (severities or ["critical", "high"]) if s.strip()]
        if not sev_list:
            sev_list = ["critical", "high"]

        # Normalize tags
        all_tags: List[str] = []
        if tags:
            all_tags.extend([t.strip().lower() for t in tags if t.strip()])
        if custom_tags:
            all_tags.extend([t.strip().lower() for t in custom_tags.split(",") if t.strip()])
        # Deduplicate tags preserving order
        unique_tags = list(dict.fromkeys(all_tags))

        # Write targets to a temporary file
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix="_nuclei_targets.txt") as tf:
            target_file_path = tf.name
            for t in targets:
                tf.write(f"{t.strip()}\n")

        cmd: List[str] = [
            self.binary_path,
            "-list", target_file_path,
            "-jsonl",
            "-severity", ",".join(sev_list),
            "-rl", str(max(10, rate_limit)),
            "-c", str(max(1, concurrency)),
            "-stats=false",
            "-silent",
        ]

        if unique_tags:
            cmd.extend(["-tags", ",".join(unique_tags)])

        if custom_flags:
            import shlex
            try:
                cmd.extend(shlex.split(custom_flags))
            except Exception as e:
                logger.warning(f"Error parsing custom flags '{custom_flags}': {e}")

        findings: List[Dict[str, Any]] = []
        raw_errors: List[str] = []

        if log_callback:
            log_callback("info", f"Starting Nuclei scan on {len(targets)} target(s) [Severities: {','.join(sev_list)}]")

        proc = None
        try:
            logger.info(f"Executing Nuclei: {' '.join(cmd)}")
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            async def read_stdout():
                assert proc.stdout is not None
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    line_str = line.decode("utf-8", errors="replace").strip()
                    if not line_str:
                        continue
                    try:
                        data = json.loads(line_str)
                        parsed_finding = self._normalize_finding(data)
                        if parsed_finding:
                            findings.append(parsed_finding)
                            if log_callback:
                                sev = parsed_finding.get("severity", "info").upper()
                                name = parsed_finding.get("name") or parsed_finding.get("template_id")
                                matched = parsed_finding.get("matched_at") or parsed_finding.get("host")
                                log_callback("warn" if sev in ["CRITICAL", "HIGH"] else "info", f"[{sev}] {name} on {matched}")
                    except json.JSONDecodeError:
                        if log_callback and ("[" in line_str or "ERR" in line_str):
                            log_callback("info", line_str)

            async def read_stderr():
                assert proc.stderr is not None
                while True:
                    line = await proc.stderr.readline()
                    if not line:
                        break
                    err_str = line.decode("utf-8", errors="replace").strip()
                    if err_str:
                        raw_errors.append(err_str)
                        logger.debug(f"Nuclei stderr: {err_str}")

            await asyncio.wait_for(
                asyncio.gather(read_stdout(), read_stderr(), proc.wait()),
                timeout=timeout
            )

            if log_callback:
                log_callback("success", f"Nuclei scan completed. Found {len(findings)} vulnerability issue(s).")

            return {
                "success": True,
                "targets": targets,
                "severities": sev_list,
                "tags": unique_tags,
                "findings": findings,
                "total_findings": len(findings),
                "error": None if not raw_errors else "\n".join(raw_errors[:5]),
            }

        except asyncio.TimeoutError:
            if proc:
                try:
                    proc.kill()
                except Exception:
                    pass
            msg = f"Nuclei scan timed out after {timeout}s"
            logger.error(msg)
            if log_callback:
                log_callback("error", msg)
            return {
                "success": False,
                "targets": targets,
                "findings": findings,
                "total_findings": len(findings),
                "error": msg,
            }
        except Exception as e:
            if proc:
                try:
                    proc.kill()
                except Exception:
                    pass
            msg = f"Nuclei execution failed: {str(e)}"
            logger.error(msg, exc_info=True)
            if log_callback:
                log_callback("error", msg)
            return {
                "success": False,
                "targets": targets,
                "findings": findings,
                "total_findings": len(findings),
                "error": msg,
            }
        finally:
            if os.path.exists(target_file_path):
                try:
                    os.remove(target_file_path)
                except Exception:
                    pass

    def _normalize_finding(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normalize a Nuclei JSONL record into standard vulnerability dict."""
        if not isinstance(record, dict):
            return None

        template_id = record.get("template-id") or record.get("templateID") or "unknown-template"
        info = record.get("info") or {}
        
        name = info.get("name") or template_id
        severity = str(info.get("severity") or "info").upper()
        description = info.get("description") or ""
        
        # Classification
        classification = info.get("classification") or {}
        cve_id = None
        cve_ids = classification.get("cve-id")
        if isinstance(cve_ids, list) and cve_ids:
            cve_id = str(cve_ids[0]).upper()
        elif isinstance(cve_ids, str) and cve_ids.strip():
            cve_id = cve_ids.strip().upper()
        elif template_id.lower().startswith("cve-"):
            cve_id = template_id.upper()

        cwe_id = None
        cwe_ids = classification.get("cwe-id")
        if isinstance(cwe_ids, list) and cwe_ids:
            cwe_id = str(cwe_ids[0]).upper()
        elif isinstance(cwe_ids, str) and cwe_ids.strip():
            cwe_id = cwe_ids.strip().upper()

        cvss_score = classification.get("cvss-score")
        if cvss_score is not None:
            try:
                cvss_score = float(cvss_score)
            except (ValueError, TypeError):
                cvss_score = None

        epss_score = classification.get("epss-score")
        if epss_score is not None:
            try:
                epss_score = float(epss_score)
            except (ValueError, TypeError):
                epss_score = None

        matched_at = record.get("matched-at") or record.get("matched") or record.get("host") or ""
        host = record.get("host") or ""
        ip = record.get("ip") or ""
        port = record.get("port")
        if port is not None:
            try:
                port = int(port)
            except (ValueError, TypeError):
                port = None

        # Extract PoC / Reference URLs
        reference = info.get("reference") or []
        references = []
        if isinstance(reference, list):
            references = [str(r) for r in reference if r]
        elif isinstance(reference, str) and reference.strip():
            references = [reference.strip()]

        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]

        curl_command = record.get("curl-command") or ""

        return {
            "template_id": template_id,
            "name": name,
            "severity": severity,
            "cve_id": cve_id or template_id,
            "description": description,
            "cwe_id": cwe_id,
            "cwe_name": ", ".join(tags[:4]) if tags else None,
            "cvss_score": cvss_score,
            "epss_score": epss_score,
            "host": host,
            "ip": ip,
            "port": port,
            "matched_at": matched_at,
            "references": references,
            "tags": tags,
            "curl_command": curl_command,
            "timestamp": record.get("timestamp"),
            "matcher_name": record.get("matcher-name"),
            "extracted_results": record.get("extracted-results"),
        }
