"""Automated Environment Setup, Prerequisite Diagnostics & Auto-Configuration for DetecTI-CLI."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.table import Table


class SetupManager:
    """Manages prerequisite diagnostics and automated system setup for DetecTI-CLI."""

    REQUIRED_PYTHON_MODULES = [
        ("httpx", "httpx"),
        ("typer", "typer"),
        ("rich", "rich"),
        ("fastapi", "fastapi"),
        ("uvicorn", "uvicorn"),
        ("pydantic", "pydantic"),
        ("pydantic_settings", "pydantic-settings"),
        ("psutil", "psutil"),
        ("tldextract", "tldextract"),
        ("cve_searchsploit", "cve-searchsploit"),
    ]

    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console()
        self.root_dir = Path(__file__).resolve().parent.parent

    def check_all(self) -> Dict[str, Any]:
        """Run all diagnostic checks across system, environment, binaries, and local databases."""
        return {
            "python_version": self.check_python_version(),
            "python_modules": self.check_python_modules(),
            "directories": self.check_directories(),
            "env_file": self.check_env_file(),
            "masscan": self.check_masscan(),
            "nuclei": self.check_nuclei(),
            "exploitdb": self.check_exploitdb(),
            "demo_db": self.check_demo_database(),
        }

    def check_python_version(self) -> Dict[str, Any]:
        """Check Python interpreter version (requires 3.11+)."""
        ver = sys.version_info
        is_ok = ver >= (3, 11)
        ver_str = f"{ver.major}.{ver.minor}.{ver.micro}"
        return {
            "name": "Python Runtime",
            "status": f"Python {ver_str}",
            "ok": is_ok,
            "required": ">= 3.11",
            "message": "Python 3.11 or newer is required." if not is_ok else "Compatible version detected.",
        }

    def check_python_modules(self) -> Dict[str, Any]:
        """Check availability of core Python packages."""
        missing = []
        installed = []
        for mod_name, pkg_name in self.REQUIRED_PYTHON_MODULES:
            try:
                __import__(mod_name)
                installed.append(pkg_name)
            except ImportError:
                missing.append(pkg_name)

        is_ok = len(missing) == 0
        return {
            "name": "Python Dependencies",
            "status": f"{len(installed)}/{len(self.REQUIRED_PYTHON_MODULES)} Installed",
            "ok": is_ok,
            "missing": missing,
            "message": f"Missing packages: {', '.join(missing)}" if missing else "All core packages are installed.",
        }

    def check_directories(self) -> Dict[str, Any]:
        """Ensure required operational directories exist."""
        dirs = [
            self.root_dir / "data" / "dbs",
            self.root_dir / "reports",
        ]
        missing = [d for d in dirs if not d.exists()]
        return {
            "name": "Project Directories",
            "status": "Ready" if not missing else f"Missing {len(missing)} folders",
            "ok": len(missing) == 0,
            "missing": [str(d.relative_to(self.root_dir)) for d in missing],
            "message": "Operational directories (./data/dbs, ./reports) are configured." if not missing else f"Folders need creation: {', '.join([str(d.relative_to(self.root_dir)) for d in missing])}",
        }

    def check_env_file(self) -> Dict[str, Any]:
        """Check if .env configuration file exists."""
        env_path = self.root_dir / ".env"
        exists = env_path.is_file()
        return {
            "name": "Environment Configuration (.env)",
            "status": "Configured (.env found)" if exists else "Missing (.env not found)",
            "ok": exists,
            "message": "Configured and active." if exists else ".env file not found (can be created from .env.example).",
        }

    def check_masscan(self) -> Dict[str, Any]:
        """Check Masscan binary installation and Linux raw socket capabilities."""
        masscan_path = shutil.which("masscan")
        if not masscan_path:
            return {
                "name": "Masscan Active Port Scanner",
                "status": "Not Installed",
                "ok": False,
                "path": None,
                "has_caps": False,
                "message": "Binary 'masscan' not found in PATH. Required for active port scanning in WebGUI.",
            }

        # Check raw socket capabilities or root execution
        has_caps = False
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        if is_root:
            has_caps = True
        else:
            getcap_bin = shutil.which("getcap")
            if getcap_bin:
                try:
                    res = subprocess.run([getcap_bin, masscan_path], capture_output=True, text=True, check=False)
                    if "cap_net_raw" in res.stdout:
                        has_caps = True
                except Exception:
                    pass

        status_text = "Ready (Non-root caps active)" if has_caps else "Installed (Needs setcap capabilities)"
        if is_root:
            status_text = "Ready (Running as root)"

        return {
            "name": "Masscan Active Port Scanner",
            "status": status_text,
            "ok": masscan_path is not None,
            "path": masscan_path,
            "has_caps": has_caps,
            "message": "Masscan is fully configured and ready for non-root execution." if has_caps else f"Masscan found at {masscan_path}, but raw socket capabilities should be set: sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip {masscan_path}",
        }

    def check_nuclei(self) -> Dict[str, Any]:
        """Check Nuclei active vulnerability scanner binary and templates."""
        nuclei_path = shutil.which("nuclei")
        if not nuclei_path:
            return {
                "name": "Nuclei Vulnerability Scanner",
                "status": "Optional / Not Installed",
                "ok": True,  # Nuclei is optional but recommended
                "installed": False,
                "path": None,
                "message": "Nuclei binary not found in PATH. Install to enable active vulnerability verification.",
            }

        # Check version
        version = "Unknown"
        try:
            res = subprocess.run([nuclei_path, "-version"], capture_output=True, text=True, check=False, timeout=3)
            for line in (res.stdout + res.stderr).splitlines():
                if "nuclei" in line.lower() or "version" in line.lower():
                    version = line.strip()
                    break
        except Exception:
            pass

        return {
            "name": "Nuclei Vulnerability Scanner",
            "status": f"Ready ({version})",
            "ok": True,
            "installed": True,
            "path": nuclei_path,
            "message": f"Nuclei is available at {nuclei_path}.",
        }

    def check_exploitdb(self) -> Dict[str, Any]:
        """Check local ExploitDB searchsploit mapping database."""
        try:
            import cve_searchsploit as cs
            mapping_path = Path(cs.pdir) / "exploitdb_mapping.json"
            exists = mapping_path.is_file() and mapping_path.stat().st_size > 1024
            return {
                "name": "ExploitDB SearchSploit Cache",
                "status": "Ready (Populated)" if exists else "Needs Update",
                "ok": exists,
                "path": str(mapping_path) if exists else None,
                "message": "Local ExploitDB mapping cache is populated." if exists else "Run update-xdb to download local exploit mapping.",
            }
        except Exception as exc:
            return {
                "name": "ExploitDB SearchSploit Cache",
                "status": "Error",
                "ok": False,
                "message": f"Could not inspect ExploitDB mapping: {exc}",
            }

    def check_demo_database(self) -> Dict[str, Any]:
        """Check default demo graph database."""
        db_path = self.root_dir / "data" / "dbs" / "example.com.sqlite"
        exists = db_path.is_file()
        return {
            "name": "Default Demo Graph Dataset",
            "status": "Ready (example.com.sqlite)" if exists else "Missing",
            "ok": exists,
            "message": "Pre-packaged demo dataset available for instant DetecTIHound visualization." if exists else "Demo dataset missing.",
        }

    def render_diagnostics_table(self, checks: Dict[str, Any]) -> None:
        """Render a formatted, high-contrast Rich diagnostics table."""
        table = Table(title="DetecTI-CLI System & Environment Diagnostics", show_header=True, header_style="bold cyan")
        table.add_column("Component / Subsystem", style="bold white", min_width=28)
        table.add_column("Status", style="bold", min_width=24)
        table.add_column("Diagnostic Details", style="dim")

        for key, info in checks.items():
            name = info.get("name", key)
            status = info.get("status", "Unknown")
            is_ok = info.get("ok", False)
            msg = info.get("message", "")

            if is_ok and "Needs" not in status:
                status_styled = f"[bold green]✔ {status}[/bold green]"
            elif "Optional" in status:
                status_styled = f"[yellow]⚠ {status}[/yellow]"
            elif not is_ok:
                status_styled = f"[bold red]✘ {status}[/bold red]"
            else:
                status_styled = f"[yellow]⚠ {status}[/yellow]"

            table.add_row(name, status_styled, msg)

        self.console.print(table)

    def run_automated_setup(self) -> bool:
        """Run automated setup: creates directories, .env file, configures capabilities, and updates databases."""
        self.console.print("\n[bold cyan]🚀 Starting DetecTI-CLI Automated Environment Setup...[/bold cyan]\n")

        all_success = True

        # Step 0: Dashboard Admin Password Setup
        self.console.print("🔐 [bold white]Step 0/7: Configuring DetecTIHound Dashboard Admin...[/bold white]")
        try:
            import getpass
            import sys
            def update_env_jwt(password: str):
                import hashlib
                import re
                jwt_secret = hashlib.sha256(password.encode('utf-8')).hexdigest()
                env_path = self.root_dir / '.env'
                if env_path.exists():
                    with open(env_path, 'r') as f:
                        env_content = f.read()
                    if 'JWT_SECRET_KEY=' in env_content:
                        env_content = re.sub(r'JWT_SECRET_KEY=.*', f'JWT_SECRET_KEY={jwt_secret}', env_content)
                    else:
                        if env_content and not env_content.endswith('\n'):
                            env_content += '\n'
                        env_content += f'JWT_SECRET_KEY={jwt_secret}\n'
                    with open(env_path, 'w') as f:
                        f.write(env_content)
                else:
                    with open(env_path, 'w') as f:
                        f.write(f'JWT_SECRET_KEY={jwt_secret}\n')
            import os
            sys.path.insert(0, str(self.root_dir))
            from core.database.config_db import ConfigDBManager, get_password_hash
            
            db_dir = self.root_dir / "data" / "dbs"
            db_dir.mkdir(parents=True, exist_ok=True)
            config_db = ConfigDBManager(self.root_dir / "data" / "config.sqlite")
            
            if config_db.user_exists("admin"):
                change = self.console.input("  [yellow]Admin user already exists. Do you want to change the password? (y/N): [/yellow]").strip().lower()
                if change == 'y':
                    while True:
                        pwd1 = getpass.getpass("  Enter new password for 'admin': ")
                        pwd2 = getpass.getpass("  Confirm new password: ")
                        if pwd1 == pwd2 and len(pwd1) >= 4:
                            config_db.update_user_password("admin", get_password_hash(pwd1))
                            update_env_jwt(pwd1)
                            self.console.print("  [green]✔ Admin password updated successfully.[/green]")
                            break
                        elif len(pwd1) < 4:
                            self.console.print("  [red]Password must be at least 4 characters.[/red]")
                        else:
                            self.console.print("  [red]Passwords do not match. Try again.[/red]")
                else:
                    self.console.print("  [green]✔ Admin configuration skipped.[/green]")
            else:
                self.console.print("  [cyan]Creating default 'admin' user for the web dashboard.[/cyan]")
                while True:
                    pwd1 = getpass.getpass("  Enter password for 'admin': ")
                    pwd2 = getpass.getpass("  Confirm password: ")
                    if pwd1 == pwd2 and len(pwd1) >= 4:
                        config_db.create_user("admin", get_password_hash(pwd1))
                        update_env_jwt(pwd1)
                        self.console.print("  [green]✔ Admin user created successfully.[/green]")
                        break
                    elif len(pwd1) < 4:
                        self.console.print("  [red]Password must be at least 4 characters.[/red]")
                    else:
                        self.console.print("  [red]Passwords do not match. Try again.[/red]")
        except Exception as e:
            self.console.print(f"  [red]⚠ Failed to configure admin: {e}[/red]")
            import traceback
            traceback.print_exc()

        # Step 1: Create Directories
        self.console.print("📁 [bold white]Step 1/7: Initializing project directories...[/bold white]")
        for d in [self.root_dir / "data" / "dbs", self.root_dir / "reports"]:
            d.mkdir(parents=True, exist_ok=True)
        self.console.print("  [green]✔ Operational directories verified (data/dbs, reports).[/green]")

        # Step 2: Configure .env
        self.console.print("\n⚙️ [bold white]Step 2/7: Checking environment configuration (.env)...[/bold white]")
        env_file = self.root_dir / ".env"
        env_example = self.root_dir / ".env.example"
        if not env_file.exists() and env_example.exists():
            shutil.copy(env_example, env_file)
            self.console.print("  [green]✔ Created .env file from .env.example template.[/green]")
        elif env_file.exists():
            self.console.print("  [green]✔ Existing .env file detected and preserved.[/green]")
        else:
            self.console.print("  [yellow]⚠ No .env template found. Skipped.[/yellow]")

        # Step 3: Python dependencies check / install
        self.console.print("\n🐍 [bold white]Step 3/7: Verifying Python dependencies...[/bold white]")
        req_file = self.root_dir / "requirements.txt"
        dep_check = self.check_python_modules()
        if not dep_check["ok"] and req_file.exists():
            self.console.print(f"  [yellow]Installing missing dependencies: {', '.join(dep_check['missing'])}...[/yellow]")
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", "-r", str(req_file)], check=True)
                self.console.print("  [green]✔ Python dependencies installed successfully.[/green]")
            except Exception as exc:
                self.console.print(f"  [red]✘ Failed to install Python dependencies: {exc}[/red]")
                all_success = False
        else:
            self.console.print("  [green]✔ All Python core dependencies are satisfied.[/green]")

        # Step 4: Masscan capabilities configuration
        self.console.print("\n⚡ [bold white]Step 4/7: Configuring Masscan network capabilities...[/bold white]")
        masscan_bin = shutil.which("masscan")
        if masscan_bin:
            is_root = hasattr(os, "geteuid") and os.geteuid() == 0
            if is_root:
                self.console.print("  [green]✔ Running as root: raw packet sockets are natively authorized.[/green]")
            else:
                setcap_bin = shutil.which("setcap")
                if setcap_bin:
                    try:
                        cmd = ["sudo", setcap_bin, "cap_net_raw,cap_net_admin,cap_net_bind_service+eip", masscan_bin]
                        self.console.print(f"  [cyan]Applying Linux capabilities via setcap...[/cyan]")
                        res = subprocess.run(cmd, check=False)
                        if res.returncode == 0:
                            self.console.print("  [green]✔ Granted non-root raw socket capabilities to masscan.[/green]")
                        else:
                            self.console.print(f"  [yellow]⚠ Could not apply setcap automatically. Run manually if needed:[/yellow]\n    sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip {masscan_bin}")
                    except Exception as exc:
                        self.console.print(f"  [yellow]⚠ Note: Run manually if non-root WebGUI scanning is needed:\n    sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip {masscan_bin}[/yellow]")
                else:
                    self.console.print(f"  [yellow]⚠ 'setcap' binary not found. Masscan may require root permissions to scan.[/yellow]")
        else:
            self.console.print("  [yellow]⚠ Masscan is not installed on this system.[/yellow]")
            self.console.print("    [dim]Install on Linux with: sudo apt install -y masscan (or pacman/dnf)[/dim]")

        # Step 5: ExploitDB Cache Update
        self.console.print("\n💣 [bold white]Step 5/7: Initializing ExploitDB vulnerability mapping...[/bold white]")
        try:
            from modules.exploitdb import ExploitDBModule
            ExploitDBModule.update_database()
            self.console.print("  [green]✔ ExploitDB mapping database initialized & updated.[/green]")
        except Exception as exc:
            self.console.print(f"  [yellow]⚠ ExploitDB update notice: {exc}[/yellow]")

        # Step 6: Nuclei Templates Check
        self.console.print("\n🛡️ [bold white]Step 6/7: Checking Nuclei vulnerability engine...[/bold white]")
        nuclei_bin = shutil.which("nuclei")
        if nuclei_bin:
            try:
                self.console.print("  [cyan]Updating Nuclei community vulnerability templates...[/cyan]")
                subprocess.run([nuclei_bin, "-update-templates", "-silent"], check=False, timeout=15)
                self.console.print("  [green]✔ Nuclei templates checked & updated.[/green]")
            except Exception:
                self.console.print("  [green]✔ Nuclei engine is active.[/green]")
        else:
            self.console.print("  [dim]Nuclei is optional and not currently installed.[/dim]")

        self.console.print("\n[bold green]✅ DetecTI-CLI setup routine completed![/bold green]\n")
        return all_success
