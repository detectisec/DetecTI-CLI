import re

path = "web/server.py"
with open(path, "r") as f:
    content = f.read()

# 1. Add imports
old_imports = r'''from core\.database\.storage import DatabaseManager
from web\.api\.routes import router as api_router'''
new_imports = '''from core.database.storage import DatabaseManager
from web.api.routes import router as api_router
from web.api.auth import router as auth_router, get_current_user
from jose import jwt, JWTError
from web.api.auth import SECRET_KEY, ALGORITHM, get_config_db'''
content = re.sub(old_imports, new_imports, content)

# 2. Add auth_router and protect api_router
old_routers = r'''    # Include API routes
    app\.include_router\(api_router, prefix="/api/v1"\)'''
new_routers = '''    # Include API routes
    from fastapi import Depends
    app.include_router(auth_router, prefix="/api/v1/auth")
    app.include_router(api_router, prefix="/api/v1", dependencies=[Depends(get_current_user)])'''
content = re.sub(old_routers, new_routers, content)

# 3. Update serve_dashboard
old_serve = r'''    @app\.get\("/"\)
    async def serve_dashboard\(\):
        """Serve the main dashboard SPA\."""
        static_dir = Path\(__file__\)\.parent / "static"
        index_file = static_dir / "index\.html"
        
        if index_file\.exists\(\):
            return FileResponse\(index_file\)
        else:
            return \{"message": "DetecTI-CLI EASM Dashboard", "status": "Dashboard files not found"\}'''

new_serve = '''    @app.get("/")
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
            return {"message": "DetecTI-CLI EASM Dashboard", "status": "Dashboard files not found"}'''
content = re.sub(old_serve, new_serve, content)

# Wait, `Request` is not imported from fastapi in server.py ?
# I see `from fastapi import FastAPI, HTTPException` ... I need to import Request
if "from fastapi import FastAPI, HTTPException, Request" not in content:
    content = content.replace("from fastapi import FastAPI, HTTPException", "from fastapi import FastAPI, HTTPException, Request")

with open(path, "w") as f:
    f.write(content)
