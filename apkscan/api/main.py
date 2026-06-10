"""FastAPI application factory."""

import logging

from fastapi import FastAPI

from apkscan import __version__
from apkscan.api import routes_auth, routes_samples, ui
from apkscan.config import get_settings

logger = logging.getLogger("apkscan.api")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="APKScan",
        version=__version__,
        description="Self-hosted Android banking-malware analysis & risk-scoring (MVP).",
    )

    app.include_router(routes_auth.router)
    app.include_router(routes_samples.router)
    app.include_router(ui.router)

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
