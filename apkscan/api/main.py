"""FastAPI application factory."""

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from apkscan import __version__
from apkscan.api import routes_auth, routes_samples
from apkscan.config import get_settings

logger = logging.getLogger("apkscan.api")

_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="APKScan",
        version=__version__,
        description="Self-hosted Android banking-malware analysis & risk-scoring (MVP).",
    )

    app.include_router(routes_auth.router)
    app.include_router(routes_samples.router)

    # --- Static files ---
    if _STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # --- Page routes (serve HTML files from static/) ---
    @app.get("/", include_in_schema=False)
    def landing():
        return FileResponse(str(_STATIC_DIR / "landing.html"))

    @app.get("/app", include_in_schema=False)
    def dashboard():
        return FileResponse(str(_STATIC_DIR / "index.html"))

    @app.get("/login", include_in_schema=False)
    def login_page():
        return FileResponse(str(_STATIC_DIR / "login.html"))

    @app.get("/report", include_in_schema=False)
    def report_page():
        return FileResponse(str(_STATIC_DIR / "report.html"))

    @app.get("/health", tags=["meta"])
    def health() -> dict:
        return {
            "status": "ok",
            "version": __version__,
            "commercial_llm_egress": settings.commercial_llm_allowed,  # must be False on-prem
            "dynamic_analysis": settings.dynamic_enabled,
            "operating_mode": settings.operating_mode,
        }

    @app.on_event("startup")
    def _startup() -> None:
        from apkscan.auth.service import ensure_default_admin
        from apkscan.db import base

        if not base.is_configured():
            base.configure()
        base.init_db()
        try:
            with base.session_scope() as session:
                created = ensure_default_admin(session)
            if created is not None:
                logger.warning("Bootstrapped default admin user '%s' — change the password.", created.username)
        except Exception:  # noqa: BLE001 - never block startup on bootstrap
            logger.exception("default-admin bootstrap skipped")

    return app


app = create_app()
