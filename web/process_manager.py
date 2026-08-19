"""Background process management for DetecTI-CLI web server."""

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Optional

import psutil


class WebServerManager:
    """Manages background web server process lifecycle."""
    
    def __init__(self, state_file: Path = Path.cwd() / ".webserver.json"):
        self.state_file = state_file
    
    def is_running(self) -> bool:
        """Check if web server is currently running."""
        if not self.state_file.exists():
            return False
        
        try:
            state = self._read_state()
            pid = state.get("pid")
            if not pid:
                return False
            
            # Check if process exists and is running
            return psutil.pid_exists(pid) and psutil.Process(pid).is_running()
        except (json.JSONDecodeError, psutil.NoSuchProcess, psutil.AccessDenied):
            return False
    
    def get_status(self) -> Optional[Dict]:
        """Get current server status information."""
        if not self.state_file.exists():
            return None
        
        try:
            state = self._read_state()
            pid = state.get("pid")
            
            if pid and psutil.pid_exists(pid):
                process = psutil.Process(pid)
                if process.is_running():
                    # Calculate uptime
                    start_time = state.get("started_at")
                    if start_time:
                        from datetime import datetime
                        started = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                        uptime = datetime.now().astimezone() - started
                        state["uptime_seconds"] = uptime.total_seconds()
                    
                    state["status"] = "RUNNING"
                    state["memory_mb"] = process.memory_info().rss / 1024 / 1024
                    return state
            
            # Process not running, clean up state file
            self._cleanup_state()
            return None
            
        except (json.JSONDecodeError, psutil.NoSuchProcess, psutil.AccessDenied):
            self._cleanup_state()
            return None
    
    def start_server(self, db_path: str, host: str = "127.0.0.1", port: int = 8000) -> bool:
        """Start web server in background process."""
        if self.is_running():
            return False  # Already running
        
        # Resolve database path
        if not os.path.isabs(db_path):
            # Check if it's in ./data/dbs/ directory
            data_db_path = Path.cwd() / "data" / "dbs" / db_path
            if data_db_path.exists():
                db_path = str(data_db_path.resolve())
            else:
                db_path = str(Path(db_path).resolve())
        
        if not Path(db_path).exists():
            raise FileNotFoundError(f"Database file not found: {db_path}")
        
        # Start server process
        cmd = [
            sys.executable, "-m", "web.server",
            "--db-path", db_path,
            "--host", host,
            "--port", str(port)
        ]
        
        try:
            # Start detached background process
            process = subprocess.Popen(
                cmd,
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=Path.cwd()
            )
            
            # Give process time to start
            time.sleep(2)
            
            # Verify it's still running
            if process.poll() is None:
                # Save state
                from datetime import datetime
                state = {
                    "pid": process.pid,
                    "port": port,
                    "host": host,
                    "db_path": db_path,
                    "started_at": datetime.now().isoformat() + "Z",
                    "status": "RUNNING"
                }
                self._write_state(state)
                return True
            else:
                return False
                
        except Exception:
            return False
    
    def stop_server(self) -> bool:
        """Stop the background web server."""
        if not self.is_running():
            return False
        
        try:
            state = self._read_state()
            pid = state.get("pid")
            
            if pid and psutil.pid_exists(pid):
                process = psutil.Process(pid)
                
                # Send SIGTERM for graceful shutdown
                process.terminate()
                
                # Wait up to 10 seconds for graceful shutdown
                try:
                    process.wait(timeout=10)
                except psutil.TimeoutExpired:
                    # Force kill if still running
                    process.kill()
                    process.wait(timeout=5)
                
                self._cleanup_state()
                return True
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self._cleanup_state()
            return True
        
        return False
    
    def _read_state(self) -> Dict:
        """Read state from JSON file."""
        return json.loads(self.state_file.read_text())
    
    def _write_state(self, state: Dict) -> None:
        """Write state to JSON file."""
        self.state_file.write_text(json.dumps(state, indent=2))
    
    def _cleanup_state(self) -> None:
        """Remove state file."""
        if self.state_file.exists():
            self.state_file.unlink()
