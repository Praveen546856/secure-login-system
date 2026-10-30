"""Application factory. Run with:  python -m uvicorn app.main:app --host 127.0.0.1 --port 8001"""
import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import Settings, get_settings
from .database import create_tables, make_engine, make_session_factory
from .middleware.rate_limit import SlidingWindowLimiter
from .middleware.request_guard import RequestGuardMiddleware
from .middleware.security_headers import SecurityHeadersMiddleware
from .routes import auth as auth_routes
from .routes import users as user_routes

logger = logging.getLogger("securelogin")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    app = FastAPI(
        title="Secure Login System API",
        version="1.0.0",
        # Interactive docs are handy in development but are switched off in production.
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/openapi.json",
    )

    engine = make_engine(settings.database_url)
    create_tables(engine)
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = make_session_factory(engine)
    app.state.ip_limiter = SlidingWindowLimiter()   # counts all auth requests per IP
    app.state.id_limiter = SlidingWindowLimiter()   # counts failures per account / user

    # Middleware order: the LAST one added runs FIRST.
    app.add_middleware(RequestGuardMiddleware, allowed_origins=settings.frontend_origins)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.frontend_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "X-CSRF-Token"],
    )
    app.add_middleware(SecurityHeadersMiddleware)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        # Field names and our own messages only; submitted values are never echoed back.
        errors = []
        for err in exc.errors()[:10]:
            field = ".".join(str(p) for p in err.get("loc", []) if p != "body")
            message = str(err.get("msg", "Invalid value")).removeprefix("Value error, ")
            errors.append({"field": field, "message": message})
        return JSONResponse(status_code=422, content={"detail": "Invalid input.", "errors": errors})

    @app.exception_handler(Exception)
    async def unexpected_handler(request: Request, exc: Exception):
        logger.error("Unexpected error: %s", type(exc).__name__)  # type only, no message or data
        return JSONResponse(status_code=500, content={"detail": "Internal server error."})

    @app.get("/api/health", tags=["health"])
    def health():
        return {"status": "ok"}

    app.include_router(auth_routes.router)
    app.include_router(user_routes.router)
    return app


try:
    app = create_app()
except Exception as exc:  # pragma: no cover - friendly startup message
    import sys
    # Pytest imports this module before it sets its own test configuration, so stay quiet there.
    if "pytest" not in sys.modules:
        print(f"\nStartup error: {exc}\nCreate backend/.env first: python -m scripts.generate_env\n")
        raise
    app = None
