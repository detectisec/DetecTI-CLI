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

TOP_100_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000,
    32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081,
    2049, 88, 79, 5800, 106, 2121, 6129, 625, 5009, 444, 902, 636, 49155, 2601, 7070, 512, 1080, 1028,
    5555, 5432, 19, 7, 7443, 6000, 3000, 2002, 513, 5357, 544, 49156, 3689, 5051, 500, 1900, 2602, 5190,
    3001, 49157, 8500, 1029, 903, 1755, 9100, 2604, 8082
]


def build_port_ranges_excluding(
    total_start: int = 0,
    total_end: int = 65535,
    excluded_ports: Optional[set[int] | list[int]] = None
) -> str:
    """Generate minimal contiguous port ranges excluding specified ports.
    
    Example:
        build_port_ranges_excluding(0, 65535, {80, 443})
        -> "0-79,81-442,444-65535"
    """
    ex_set = {int(p) for p in (excluded_ports or set()) if total_start <= int(p) <= total_end}
    if not ex_set:
        return f"{total_start}-{total_end}" if total_start != total_end else str(total_start)

    sorted_excluded = sorted(ex_set)
    ranges = []
    current_start = total_start

    for p in sorted_excluded:
        if p > current_start:
            if p - 1 == current_start:
                ranges.append(str(current_start))
            else:
                ranges.append(f"{current_start}-{p - 1}")
        current_start = p + 1

    if current_start <= total_end:
        if current_start == total_end:
            ranges.append(str(current_start))
        else:
            ranges.append(f"{current_start}-{total_end}")

    return ",".join(ranges)


def parse_port_spec_to_set(ports_spec: Optional[str]) -> set[int]:
    """Parse a port specification string into a discrete set of port integers."""
    if not ports_spec or not ports_spec.strip():
        return set(TOP_100_PORTS)

    spec = ports_spec.strip()
    if spec.startswith("-p"):
        spec = spec[2:].strip()

    if spec in ("-", "all", "0-65535", "-p0-65535"):
        return set(range(0, 65536))
    if spec in ("1-65535", "-p1-65535"):
        return set(range(1, 65536))

    if spec.startswith("--top-ports"):
        parts = spec.split()
        count = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 100
        return set(TOP_100_PORTS[:min(count, len(TOP_100_PORTS))])

    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            try:
                start_s, end_s = chunk.split("-", 1)
                s = int(start_s.strip())
                e = int(end_s.strip())
                if s <= e:
                    ports.update(range(s, e + 1))
            except ValueError:
                continue
        elif chunk.isdigit():
            ports.add(int(chunk))

    return ports


def filter_ports_excluding(
    ports_spec: Optional[str],
    excluded_ports: Optional[set[int] | list[int]] = None
) -> tuple[Optional[str], int, int]:
    """Filter out excluded ports from any port specification.
    
    Returns:
        (filtered_ports_arg, remaining_count, excluded_count)
    """
    excluded_set = {int(p) for p in (excluded_ports or set())}
    if not ports_spec:
        ports_spec = "--top-ports 100"

    clean_spec = ports_spec.strip()
    if clean_spec.startswith("-p"):
        clean_spec = clean_spec[2:].strip()

    is_all_ports = clean_spec in ("-", "all", "0-65535", "1-65535", "-p0-65535", "-p1-65535")
    
    if is_all_ports:
        start_p = 1 if "1-65535" in clean_spec else 0
        filtered_arg = build_port_ranges_excluding(start_p, 65535, excluded_set)
        total_p = (65535 - start_p + 1)
        ex_count = len([p for p in excluded_set if start_p <= p <= 65535])
        remaining = max(0, total_p - ex_count)
        return filtered_arg, remaining, ex_count

    target_ports = parse_port_spec_to_set(ports_spec)
    initial_count = len(target_ports)
    remaining_ports = target_ports - excluded_set
    excluded_count = initial_count - len(remaining_ports)

    if not remaining_ports:
        return None, 0, excluded_count

    # If top-ports was asked without any exclusions
    if ports_spec.strip().startswith("--top-ports") and excluded_count == 0:
        return ports_spec.strip(), len(remaining_ports), 0

    sorted_rem = sorted(remaining_ports)
    ranges = []
    r_start = sorted_rem[0]
    r_prev = sorted_rem[0]
    
    for p in sorted_rem[1:]:
        if p == r_prev + 1:
            r_prev = p
        else:
            if r_start == r_prev:
                ranges.append(str(r_start))
            else:
                ranges.append(f"{r_start}-{r_prev}")
            r_start = p
            r_prev = p
    if r_start == r_prev:
        ranges.append(str(r_start))
    else:
        ranges.append(f"{r_start}-{r_prev}")

    return ",".join(ranges), len(remaining_ports), excluded_count


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
        target_ip: Optional[str] = None,
        ports: Optional[str] = None,
        rate: int = 1000,
        disable_ping: bool = True,
        banners: bool = True,
        custom_flags: Optional[str] = None,
        timeout: float = 120.0,
        target: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute masscan against a specific target IP and return parsed findings."""
        target_ip = target_ip or target or ""
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
            if p_clean in ("-p-", "-", "all", "0-65535", "1-65535", "-p0-65535", "-p1-65535"):
                cmd.extend(["-p", "0-65535"])
            elif p_clean.startswith("-p"):
                val = p_clean[2:].strip()
                if val in ("-", "all", "0-65535", "1-65535"):
                    cmd.extend(["-p", "0-65535"])
                else:
                    cmd.extend(["-p", val])
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
                # Parse all ports discovered by masscan before timeout occurred
                discovered_ports = self._parse_json_file(temp_out_path, target_ip)
                return {
                    "success": len(discovered_ports) > 0,
                    "target": target_ip,
                    "error": f"Masscan execution timed out after {timeout} seconds",
                    "ports": discovered_ports,
                    "open_ports": discovered_ports,
                    "count": len(discovered_ports),
                }

            stderr_text = stderr_bytes.decode("utf-8", errors="replace")
            
            # Check exit code and parse findings
            open_ports = self._parse_json_file(temp_out_path, target_ip)

            # Check if there was a permission error
            if "requires root privileges" in stderr_text or "permission denied" in stderr_text.lower():
                return {
                    "success": False,
                    "target": target_ip,
                    "error": "Masscan requires root or CAP_NET_RAW privileges to run raw packet scans",
                    "ports": [],
                    "open_ports": [],
                }

            return {
                "success": True,
                "target": target_ip,
                "ports": open_ports,
                "open_ports": open_ports,
                "count": len(open_ports),
                "command": " ".join(cmd),
            }

        except Exception as exc:
            logger.error(f"Error executing masscan on {target_ip}: {exc}")
            discovered_ports = self._parse_json_file(temp_out_path, target_ip)
            return {
                "success": len(discovered_ports) > 0,
                "target": target_ip,
                "error": str(exc),
                "ports": discovered_ports,
                "open_ports": discovered_ports,
                "count": len(discovered_ports),
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

            # Handle Masscan JSON quirks (trailing commas before closing bracket, mid-stream EOF)
            import re
            content = re.sub(r',\s*([\]\}])', r'\1', content)
            if not content.endswith("]") and not content.endswith("}"):
                content += "\n]"
            if not content.startswith("[") and not content.startswith("{"):
                content = "[" + content

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
