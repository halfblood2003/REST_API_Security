from datetime import datetime, timedelta, timezone
from http import HTTPStatus

from fastapi import HTTPException
from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError

from app.config import get_settings


def _build_token(subject: str, token_type: str, expires_delta: timedelta) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "type": token_type,
        "iat": now,
        "exp": now + expires_delta,
    }
    return jwt.encode(
        payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
    )


def create_access_token(subject: str, expires_delta: timedelta | None = None) -> str:
    settings = get_settings()
    expiry = expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    return _build_token(subject=subject, token_type="access", expires_delta=expiry)


def create_refresh_token(subject: str, expires_delta: timedelta | None = None) -> str:
    settings = get_settings()
    expiry = expires_delta or timedelta(days=settings.refresh_token_expire_days)
    return _build_token(subject=subject, token_type="refresh", expires_delta=expiry)


def decode_token(token: str, expected_type: str) -> dict[str, str]:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
    except ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED,
            detail="Token expired",
        ) from exc
    except JWTError as exc:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED,
            detail="Invalid token",
        ) from exc

    token_type = payload.get("type")
    subject = payload.get("sub")

    if token_type != expected_type or not subject:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED,
            detail="Invalid token",
        )

    return {"sub": str(subject), "type": str(token_type)}
