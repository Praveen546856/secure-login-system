"""Request guard: cheap checks that run before any route.

1. Body size limit (16 KB): auth requests are tiny.
2. For state-changing methods (POST/PUT/PATCH/DELETE):
   a. If the browser sends an Origin header it must be one of our frontend origins (CSRF defence).
   b. If the browser sends Sec-Fetch-Site it must not be "cross-site".
   c. A request body must be JSON (application/json). A cross-site <form> cannot send JSON,
      and a cross-site fetch with JSON triggers a CORS preflight that we do not allow.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

MAX_BODY_BYTES = 16 * 1024
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _reject(status: int, detail: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"detail": detail})


class RequestGuardMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, allowed_origins):
        super().__init__(app)
        self.allowed_origins = {o.rstrip("/") for o in allowed_origins}

    async def dispatch(self, request, call_next):
        length = request.headers.get("content-length")
        if length is not None:
            if not length.isdigit() or int(length) > MAX_BODY_BYTES:
                return _reject(413, "Request body too large.")

        if request.method in UNSAFE_METHODS:
            origin = request.headers.get("origin")
            if origin is not None and origin.rstrip("/") not in self.allowed_origins:
                return _reject(403, "Origin not allowed.")
            if request.headers.get("sec-fetch-site") == "cross-site":
                return _reject(403, "Cross-site requests are not allowed.")

            content_type = request.headers.get("content-type", "")
            has_body = length not in (None, "0")
            if (content_type and not content_type.lower().startswith("application/json")) or (
                not content_type and has_body
            ):
                return _reject(415, "Content-Type must be application/json.")

        return await call_next(request)
