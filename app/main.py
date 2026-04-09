from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable
from http import HTTPStatus

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.config import get_settings
from app.database import Base, engine
from app.routers import auth, items


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )
        return response


class CSRFMiddleware(BaseHTTPMiddleware):
    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
    EXEMPT_PATHS = {
        "/register",
        "/login",
        "/openapi.json",
        "/docs",
        "/docs/oauth2-redirect",
        "/redoc",
    }

    @staticmethod
    def _sign_token(raw_token: str, secret_key: str) -> str:
        signature = hmac.new(
            secret_key.encode("utf-8"), raw_token.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return f"{raw_token}.{signature}"

    @staticmethod
    def _verify_signed_token(signed_token: str, secret_key: str) -> str | None:
        if "." not in signed_token:
            return None

        token, provided_signature = signed_token.rsplit(".", 1)
        expected_signature = hmac.new(
            secret_key.encode("utf-8"), token.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(provided_signature, expected_signature):
            return None
        return token

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        settings = get_settings()
        cookie_name = "csrf_token"

        csrf_cookie = request.cookies.get(cookie_name)
        csrf_token = None
        if csrf_cookie:
            csrf_token = self._verify_signed_token(csrf_cookie, settings.jwt_secret_key)

        if not csrf_token:
            csrf_token = secrets.token_urlsafe(32)

        request.state.csrf_token = csrf_token

        state_changing_request = request.method.upper() not in self.SAFE_METHODS
        if state_changing_request and request.url.path not in self.EXEMPT_PATHS:
            header_token = request.headers.get("X-CSRF-Token")
            if not header_token or header_token != csrf_token:
                raise HTTPException(
                    status_code=HTTPStatus.FORBIDDEN,
                    detail="CSRF validation failed",
                )

        response = await call_next(request)
        signed_token = self._sign_token(csrf_token, settings.jwt_secret_key)
        response.set_cookie(
            key=cookie_name,
            value=signed_token,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=3600,
            path="/",
        )
        return response


app = FastAPI(title="Secure FastAPI JWT API", version="1.0.0")

app.add_middleware(CSRFMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(auth.router)
app.include_router(items.router)


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    settings = get_settings()

    if settings.environment.lower() == "development":
        return JSONResponse(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error", "error": str(exc)},
        )

    return JSONResponse(
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )
