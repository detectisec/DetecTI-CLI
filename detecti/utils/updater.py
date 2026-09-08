import json
import time
from pathlib import Path
from detecti.config import DETECTI_HOME

def check_for_updates(current_version: str) -> None:
    """Check PyPI for a newer version of detecti-cli, caching the result to avoid spamming."""
    cache_file = DETECTI_HOME / "last_update_check.json"
    
    # Check if we should skip network request (e.g., checked within last 12 hours)
    if cache_file.exists():
        try:
            data = json.loads(cache_file.read_text())
            if time.time() - data.get("last_check", 0) < 43200: # 12 hours
                if data.get("newer_version"):
                    _print_update_warning(current_version, data["newer_version"])
                return
        except Exception:
            pass

    # Perform request
    try:
        import requests
        resp = requests.get("https://pypi.org/pypi/detecti-cli/json", timeout=2.0)
        if resp.status_code == 200:
            latest_version = resp.json()["info"]["version"]
            
            from packaging.version import parse
            is_newer = parse(latest_version) > parse(current_version)
            
            # Save to cache
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps({
                "last_check": time.time(),
                "latest_version": latest_version,
                "newer_version": latest_version if is_newer else None
            }))
            
            if is_newer:
                _print_update_warning(current_version, latest_version)
    except Exception:
        # Silently fail on network/timeout errors to not disrupt CLI workflow
        pass

def _print_update_warning(current: str, latest: str) -> None:
    from detecti.utils.logger import console
    from rich.panel import Panel
    console.print(Panel(
        f"[bold yellow]Aviso:[/bold yellow] Uma nova versão do [bold cyan]DetecTI-CLI[/bold cyan] está disponível ([dim]{current}[/dim] -> [bold green]{latest}[/bold green])\n"
        f"Execute [bold white]pip install --upgrade detecti-cli[/bold white] para atualizar.",
        border_style="yellow",
        padding=(0, 2)
    ))
