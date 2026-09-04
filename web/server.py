"""FastAPI web server for DetecTI-CLI EASM dashboard."""

import argparse
import sys
from pathlib import Path
from typing import Dict

# Add project root to Python path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

try:
    import uvicorn
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse
    from fastapi.middleware.cors import CORSMiddleware
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    # Create dummy classes for type hints
    class FastAPI:
        pass
    class HTTPException(Exception):
        pass

from core.database.storage import DatabaseManager
from web.api.routes import router as api_router
from web.api.auth import router as auth_router, get_current_user
from jose import jwt, JWTError
from web.api.auth import SECRET_KEY, ALGORITHM, get_config_db


def create_app(db_path: str = None) -> FastAPI:
    """Create FastAPI application with optional database connection."""
    if not FASTAPI_AVAILABLE:
        raise ImportError("FastAPI and uvicorn are required for web server functionality. Install with: pip install fastapi uvicorn")
    
    from fastapi import FastAPI
    app = FastAPI(
        title="DetecTI-CLI EASM Dashboard",
        description="Interactive External Attack Surface Management Dashboard",
        version="2.0.0"
    )
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Check if db_path was provided or auto-discover from data/dbs/
    resolved_db_path = None
    if db_path:
        p = Path(db_path)
        if not p.is_absolute():
            candidate = Path.cwd() / "data" / "dbs" / db_path
            if candidate.exists():
                p = candidate
            elif not db_path.endswith(".sqlite"):
                cand_ext = Path.cwd() / "data" / "dbs" / f"{db_path}.sqlite"
                if cand_ext.exists():
                    p = cand_ext
        if p.exists():
            resolved_db_path = str(p.resolve())
    
    if not resolved_db_path:
        # Auto-discover databases in data/dbs/ - Prioritize example.com.sqlite as default if present
        dbs_dir = Path.cwd() / "data" / "dbs"
        if dbs_dir.exists():
            example_db = dbs_dir / "example.com.sqlite"
            if example_db.exists():
                resolved_db_path = str(example_db.resolve())
            else:
                existing_dbs = sorted(list(dbs_dir.glob("*.sqlite")))
                if existing_dbs:
                    resolved_db_path = str(existing_dbs[0].resolve())
    
    # Store database manager in app state
    if resolved_db_path and Path(resolved_db_path).exists():
        app.state.db_manager = DatabaseManager(Path(resolved_db_path))
        app.state.db_path = resolved_db_path
    else:
        app.state.db_manager = None
        app.state.db_path = None
    
    # Include API routes
    from fastapi import Depends
    app.include_router(auth_router, prefix="/api/v1/auth")
    app.include_router(api_router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
    
    # Serve static files
    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")
    
    @app.get("/")
    async def serve_dashboard(request: Request):
        """Serve the main dashboard SPA or login page."""
        static_dir = Path(__file__).parent / "static"
        
        # Check authentication
        token = request.cookies.get("detecti_token")
        authenticated = False
        if token:
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                username = payload.get("sub")
                if username:
                    config_db = get_config_db()
                    if config_db.user_exists(username):
                        authenticated = True
            except JWTError:
                pass
                
        if not authenticated:
            login_file = static_dir / "login.html"
            if login_file.exists():
                return FileResponse(login_file)
            else:
                return {"message": "Login required but login.html not found"}
                
        index_file = static_dir / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        else:
            return {"message": "DetecTI-CLI EASM Dashboard", "status": "Dashboard files not found"}
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "database": app.state.db_path,
            "version": "2.0.0"
        }
    
    return app


def main():
    """Main entry point for web server."""
    if not FASTAPI_AVAILABLE:
        print("FastAPI and uvicorn are required for web server functionality.", file=sys.stderr)
        print("Install with: pip install fastapi uvicorn", file=sys.stderr)
        sys.exit(1)
    
    parser = argparse.ArgumentParser(description="DetecTI-CLI Web Server")
    parser.add_argument("--db-path", default=None, help="Path to SQLite database (optional)")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    
    args = parser.parse_args()
    
    try:
        app = create_app(args.db_path)
        
        # Run server
        import uvicorn
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            log_level="warning",  # Reduce log noise
            access_log=False
        )

    except Exception as e:
        print(f"Failed to start server: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
