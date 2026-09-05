#!/usr/bin/env python3
"""
DetecTI-CLI - Automated Installer & Bootstrapper
This script installs the necessary dependencies and delegates the
system configuration to the SetupManager.
"""
import os
import sys
import subprocess
from pathlib import Path

def print_step(msg: str) -> None:
    print(f"\n\033[1;34m[+]\033[0m \033[1;37m{msg}\033[0m")

def print_success(msg: str) -> None:
    print(f"\033[1;32m[✔]\033[0m {msg}")

def print_error(msg: str) -> None:
    print(f"\033[1;31m[✘]\033[0m \033[1;31m{msg}\033[0m")

def print_banner() -> None:
    banner = """
 ██████╗ ███████╗████████╗███████╗ ██████╗████████╗██╗       ██████╗██╗     ██╗
 ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██║      ██╔════╝██║     ██║
 ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║█████╗██║     ██║     ██║
 ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║╚════╝██║     ██║     ██║
 ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ██║      ╚██████╗███████╗██║
 ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   ╚═╝       ╚═════╝╚══════╝╚═╝
                                                                                
 DetecTI - Cyber Lead Intelligence Installer
 Powered by DetecTI Security - https://detecti.com.br
"""
    print(f"\033[1;36m{banner}\033[0m")

def install_dependencies() -> None:
    root_dir = Path(__file__).resolve().parent
    req_file = root_dir / "requirements.txt"
    if req_file.exists():
        print_step("Bootstrapping Python dependencies...")
        try:
            # First attempt standard installation
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", str(req_file)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode != 0:
                if "externally-managed-environment" in result.stderr:
                    # PEP 668 bypass for Debian/Kali/Ubuntu modern versions
                    subprocess.check_call(
                        [sys.executable, "-m", "pip", "install", "--break-system-packages", "-r", str(req_file)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.STDOUT
                    )
                else:
                    print_error("Failed to install dependencies.")
                    print(result.stderr)
                    sys.exit(1)
                    
            print_success("Core dependencies installed successfully.")
        except subprocess.CalledProcessError as e:
            print_error("Failed to install dependencies.")
            print_error("Try running: pip3 install -r requirements.txt manually.")
            sys.exit(1)
    else:
        print_error(f"requirements.txt not found at {req_file}")
        sys.exit(1)

def run_setup() -> None:
    print_step("Initializing DetecTI-CLI Setup Routine...")
    # Now that dependencies are guaranteed, we can safely import them
    try:
        from rich.console import Console
        from utils.setup import SetupManager
        
        console = Console()
        setup_mgr = SetupManager(console=console)
        
        success = setup_mgr.run_automated_setup()
        
        print("\n")
        console.rule("[bold cyan]Verification Diagnostics[/bold cyan]")
        checks = setup_mgr.check_all()
        setup_mgr.render_diagnostics_table(checks)
        
        if not success:
            console.print("\n[yellow]⚠ Setup completed, but some components reported errors. Please review the logs above.[/yellow]")
            
    except ImportError as e:
        print_error(f"Failed to load setup module. Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print_banner()
    
    # Enforce running from the repository root
    if not (Path(__file__).resolve().parent / "utils" / "setup.py").exists():
        print_error("Installer must be run from the root of the DetecTI-CLI repository.")
        sys.exit(1)
        
    install_dependencies()
    run_setup()
