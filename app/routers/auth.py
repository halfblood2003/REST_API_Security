from datetime import timedelta
from http import HTTPStatus

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.auth.jwt_handler import create_access_token, create_refresh_token, decode_token
from app.auth.password import hash_password, verify_password
from app.config import get_settings
from app.database import get_db
from app.models import User
from app.schemas import (
    CSRFTokenResponse,
    LoginRequest,
    TokenResponse,
    UserCreate,
    UserRead,
)

router = APIRouter(tags=["auth"])


@router.post("/register", response_model=UserRead, status_code=HTTPStatus.CREATED)
def register_user(payload: UserCreate, db: Session = Depends(get_db)) -> User:
    existing_user = (
        db.query(User)
        .filter((User.username == payload.username) | (User.email == payload.email))
        .first()
    )
    if existing_user is not None:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Username or email already exists",
        )

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login_user(
    payload: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse:
    settings = get_settings()
    user = db.query(User).filter(User.username == payload.username).first()

    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED,
            detail="Invalid credentials",
        )

    access_token = create_access_token(subject=user.username)
    refresh_token = create_refresh_token(subject=user.username)

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
        path="/",
    )

    return TokenResponse(
        access_token=access_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh_access_token(
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    settings = get_settings()
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED,
            detail="Refresh token missing",
        )

    payload = decode_token(token=refresh_token, expected_type="refresh")
    username = payload["sub"]
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED,
            detail="Invalid token subject",
        )

    new_access_token = create_access_token(
        subject=user.username,
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
    )
    return TokenResponse(
        access_token=new_access_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/logout", status_code=HTTPStatus.NO_CONTENT)
def logout_user(response: Response, _: User = Depends(get_current_user)) -> Response:
    response.delete_cookie(key="refresh_token", path="/")
    return response


@router.get("/csrf-token", response_model=CSRFTokenResponse)
def get_csrf_token(
    request: Request,
    _: User = Depends(get_current_user),
) -> CSRFTokenResponse:
    token = getattr(request.state, "csrf_token", "")
    return CSRFTokenResponse(csrf_token=token)
