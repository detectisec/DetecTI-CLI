"""FastAPI web server for DetecTI-CLI EASM dashboard."""

import argparse
import sys
from pathlib import Path
from typing import Dict

try:
    import uvicorn
    from fastapi import FastAPI, HTTPException
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


def create_app(db_path: str) -> FastAPI:
    """Create FastAPI application with database connection."""
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
    
    # Verify database exists
    if not Path(db_path).exists():
        raise FileNotFoundError(f"Database file not found: {db_path}")
    
    # Store database manager in app state
    app.state.db_manager = DatabaseManager(Path(db_path))
    app.state.db_path = db_path
    
    # Include API routes
    app.include_router(api_router, prefix="/api/v1")
    
    # Serve static files
    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")
    
    @app.get("/")
    async def serve_dashboard():
        """Serve the main dashboard SPA."""
        static_dir = Path(__file__).parent / "static"
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
            "database": db_path,
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
    parser.add_argument("--db-path", required=True, help="Path to SQLite database")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
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
