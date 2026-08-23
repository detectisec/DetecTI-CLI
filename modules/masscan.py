"""Masscan active network port scanner module and runner."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("detecti.masscan")


DEFAULT_HTTP_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"


class MasscanRunner:
    """Async Masscan execution engine for targeted active port scanning."""

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = binary_path or shutil.which("masscan") or "/usr/bin/masscan"

    def is_available(self) -> bool:
        """Check if masscan executable exists and is accessible."""
        if not self.binary_path:
            return False
        p = Path(self.binary_path)
        return p.exists() and os.access(str(p), os.X_OK)

    def check_permissions(self) -> Dict[str, Any]:
        """Verify binary availability and execution permissions."""
        available = self.is_available()
        is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
        return {
            "available": available,
            "binary_path": self.binary_path if available else None,
            "is_root": is_root,
            "can_run": available,
            "message": (
                "Masscan ready"
                if available
                else "Masscan binary not found on system (install with: apt-get install masscan)"
            ),
        }

    async def scan_target(
        self,
        target_ip: str,
        ports: Optional[str] = None,
        rate: int = 1000,
        disable_ping: bool = True,
        banners: bool = True,
        custom_flags: Optional[str] = None,
        timeout: float = 120.0,
    ) -> Dict[str, Any]:
        """Execute masscan against a specific target IP and return parsed findings."""
        if not self.is_available():
            return {
                "success": False,
                "target": target_ip,
                "error": "Masscan executable not found on host system",
                "ports": [],
            }

        target_ip = target_ip.strip()
        temp_out = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        temp_out_path = temp_out.name
        temp_out.close()

        cmd = [self.binary_path, target_ip]

        # Port specification
        if ports:
            p_clean = ports.strip()
            if p_clean.startswith("-p"):
                cmd.extend(["-p", p_clean[2:].strip()])
            elif p_clean.startswith("--top-ports"):
                parts = p_clean.split()
                cmd.extend(["--top-ports", parts[1] if len(parts) > 1 else "100"])
            else:
                cmd.extend(["-p", p_clean])
        else:
            cmd.extend(["--top-ports", "100"])

        # Rate control
        cmd.extend(["--rate", str(max(10, min(rate, 25000)))])

        # Disable ping (-Pn)
        if disable_ping:
            cmd.append("-Pn")

        # Banner grabbing & HTTP User-Agent evasion
        if banners:
            cmd.append("--banners")
            cmd.extend(["--http-user-agent", DEFAULT_HTTP_USER_AGENT])

        # Custom flags
        if custom_flags:
            import shlex
            try:
                extra_args = shlex.split(custom_flags.strip())
                cmd.extend(extra_args)
            except Exception as e:
                logger.warning(f"Error parsing custom masscan flags: {e}")

        # JSON output to temp file
        cmd.extend(["-oJ", temp_out_path])

        logger.info(f"Executing masscan command: {' '.join(cmd)}")

        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                if proc:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                return {
                    "success": False,
                    "target": target_ip,
                    "error": f"Masscan execution timed out after {timeout} seconds",
                    "ports": [],
                }

            stderr_text = stderr_bytes.decode("utf-8", errors="replace")
            
            # Check exit code
            # Note: Masscan may exit with code 0 or 1 on completion
            open_ports = self._parse_json_file(temp_out_path, target_ip)

            # Check if there was a permission error
            if "requires root privileges" in stderr_text or "permission denied" in stderr_text.lower():
                return {
                    "success": False,
                    "target": target_ip,
                    "error": "Masscan requires root or CAP_NET_RAW privileges to run raw packet scans",
                    "ports": [],
                }

            return {
                "success": True,
                "target": target_ip,
                "ports": open_ports,
                "count": len(open_ports),
                "command": " ".join(cmd),
            }

        except Exception as exc:
            logger.error(f"Error executing masscan on {target_ip}: {exc}")
            return {
                "success": False,
                "target": target_ip,
                "error": str(exc),
                "ports": [],
            }
        finally:
            # Clean up temp file
            try:
                if os.path.exists(temp_out_path):
                    os.remove(temp_out_path)
            except Exception:
                pass

    def _parse_json_file(self, filepath: str, default_ip: str) -> List[Dict[str, Any]]:
        """Parse masscan JSON output safely, consolidating port records and extracting banners."""
        if not os.path.exists(filepath):
            return []

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read().strip()

            if not content:
                return []

            # Handle Masscan JSON quirks (e.g. trailing commas before closing bracket)
            if content.endswith(",\n]"):
                content = content[:-3] + "\n]"
            elif content.endswith(",]"):
                content = content[:-2] + "]"
            elif not content.endswith("]") and not content.endswith("}"):
                # If interrupted mid-output, attempt to close bracket
                content += "\n]"

            data = json.loads(content)
            # Use dictionary keyed by (ip, port, proto) to merge duplicate masscan records (status + banners)
            merged_ports: Dict[tuple, Dict[str, Any]] = {}

            for item in data:
                ip = item.get("ip", default_ip)
                for p in item.get("ports", []):
                    port_num = p.get("port")
                    if port_num is None:
                        continue

                    proto = p.get("proto", "tcp").lower()
                    status = p.get("status", "open")
                    ttl = p.get("ttl")
                    
                    service_info = p.get("service", {})
                    service_name = service_info.get("name") if isinstance(service_info, dict) else None
                    banner = service_info.get("banner") if isinstance(service_info, dict) else None

                    key = (ip, int(port_num), proto)
                    if key not in merged_ports:
                        inferred_name = service_name or self._infer_service_name(int(port_num))
                        merged_ports[key] = {
                            "ip": ip,
                            "port": int(port_num),
                            "protocol": proto,
                            "status": status,
                            "ttl": ttl,
                            "service_name": inferred_name,
                            "product": "",
                            "version": "",
                            "banner": banner or "",
                            "ssl": (int(port_num) == 443 or "https" in (inferred_name or "").lower() or "ssl" in (inferred_name or "").lower()),
                            "source": "Masscan",
                        }
                    else:
                        entry = merged_ports[key]
                        if status:
                            entry["status"] = status
                        if ttl:
                            entry["ttl"] = ttl
                        if service_name and (not entry["service_name"] or entry["service_name"].startswith("service-")):
                            entry["service_name"] = service_name
                        if banner and len(banner) > len(entry.get("banner", "")):
                            entry["banner"] = banner
                        if int(port_num) == 443 or "https" in (entry["service_name"] or "").lower() or "ssl" in (entry["service_name"] or "").lower() or (service_name and "ssl" in service_name.lower()):
                            entry["ssl"] = True

            # Extract product and version from banner if available
            results: List[Dict[str, Any]] = []
            for entry in merged_ports.values():
                banner_str = entry.get("banner", "")
                if banner_str:
                    prod, ver = self._extract_product_version(banner_str, entry["port"])
                    entry["product"] = prod
                    entry["version"] = ver
                results.append(entry)

            # Sort by port number
            results.sort(key=lambda x: x["port"])
            return results

        except Exception as e:
            logger.warning(f"Error parsing masscan JSON output: {e}")
            return []

    @staticmethod
    def _extract_product_version(banner: str, port: int) -> tuple[str, str]:
        """Extract product name and version string from banner."""
        import re
        if not banner:
            return "", ""
        
        banner_clean = banner.strip()
        
        # 1. HTTP Server Header: Server: <name>/<version>
        server_m = re.search(r"Server:\s*([^\r\n]+)", banner_clean, re.IGNORECASE)
        if server_m:
            server_val = server_m.group(1).strip()
            parts = server_val.split("/", 1)
            prod = parts[0].strip()
            ver = ""
            if len(parts) > 1:
                ver = parts[1].split()[0].strip()
            return prod, ver
        
        # 2. SSH Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu
        if banner_clean.startswith("SSH-"):
            parts = banner_clean.split("-", 2)
            if len(parts) >= 3:
                prod_ver = parts[2].split()[0].strip()
                if "_" in prod_ver:
                    p, v = prod_ver.split("_", 1)
                    return p, v
                return prod_ver, ""

        # 3. Simple banner like 'cloudflare' or 'nginx'
        first_line = banner_clean.splitlines()[0].strip() if banner_clean else ""
        if len(first_line) < 40 and not first_line.startswith("HTTP/"):
            parts = first_line.split("/", 1)
            if len(parts) == 2:
                return parts[0].strip(), parts[1].split()[0].strip()
            return first_line, ""

        return "", ""

    @staticmethod
    def _infer_service_name(port: int) -> str:
        """Infer common service name from port number."""
        common = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            445: "microsoft-ds",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            1521: "oracle",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc",
            6379: "redis",
            8000: "http-alt",
            8080: "http-proxy",
            8443: "https-alt",
            8888: "http-alt",
            9200: "elasticsearch",
            27017: "mongodb",
        }
        return common.get(port, f"service-{port}")
