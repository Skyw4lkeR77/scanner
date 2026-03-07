"""FastAPI application entry point."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.config import settings
from app.database import init_db
from app.middleware import SecurityHeadersMiddleware, RateLimitMiddleware
from app.routers import auth, admin, scan, findings, dashboard
import os

app = FastAPI(
    title="OWASP TOP 10 ONLINE SCANNER",
    description="Security vulnerability scanner powered by Nuclei with OWASP Top 10 categorization",
    version="1.0.0",
    docs_url="/api/docs" if settings.APP_ENV == "development" else None,
    redoc_url="/api/redoc" if settings.APP_ENV == "development" else None,
)

# ─── Middleware ──────────────────────────────────────────────────────────────
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware, max_requests=settings.RATE_LIMIT_SCAN, window_seconds=60)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"] if settings.APP_ENV == "development" else settings.ALLOWED_HOSTS.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Routers ────────────────────────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(scan.router)
app.include_router(findings.router)
app.include_router(dashboard.router)


# ─── Health check ───────────────────────────────────────────────────────────
@app.get("/api/health")
def health_check():
    return {"status": "ok", "app": "OWASP TOP 10 ONLINE SCANNER"}


# ─── Serve frontend static files ────────────────────────────────────────────
frontend_dist = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "frontend", "dist")
if os.path.isdir(frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        """Serve frontend SPA — all non-API routes go to index.html."""
        file_path = os.path.join(frontend_dist, full_path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(frontend_dist, "index.html"))


# ─── Startup ────────────────────────────────────────────────────────────────
@app.on_event("startup")
def on_startup():
    init_db()
