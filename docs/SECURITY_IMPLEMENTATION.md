# Security Implementation Details

## 1. IDOR Fix

### What was vulnerable

The vulnerable pattern in object APIs is to fetch records by URL identifier only, for example using `/items/{item_id}` and returning the record immediately if it exists. That approach trusts direct object references from the request path and ignores ownership.

### Before (vulnerable pattern)

```python
item = db.query(Item).filter(Item.id == item_id).first()
if not item:
    raise HTTPException(status_code=404)
return item
```

### After (secure implementation)

```python
item = db.query(Item).filter(Item.id == item_id).first()
if item is None:
    raise HTTPException(status_code=404, detail="Item not found")
if item.owner_id != current_user.id:
    raise HTTPException(status_code=403, detail="Access denied")
return item
```

This ownership check is enforced for all item-by-ID routes (`GET`, `PUT`, `DELETE`) through shared helper functions in the items router. The server never trusts `item_id` alone and always performs DB-level ownership validation.

### How it is tested

`tests/test_idor.py` includes:
- authenticated user A cannot read user B item (expects `403`)
- authenticated user can read own item (expects `200`)
- unauthenticated request is blocked (expects `401`)

## 2. CSRF Fix

### What was vulnerable

State-changing endpoints (`POST`, `PUT`, `DELETE`, `PATCH`) can be abused if the browser sends credentials automatically and there is no anti-CSRF token verification.

### Middleware implementation

A dedicated CSRF middleware was added with these behaviors:
- Creates a random CSRF token if one does not exist.
- Stores a signed CSRF token in an `HttpOnly`, `Secure`, `SameSite=Strict` cookie.
- Validates `X-CSRF-Token` header for every state-changing request.
- Rejects missing or mismatched token with `403`.

```python
if state_changing_request and request.url.path not in self.EXEMPT_PATHS:
    header_token = request.headers.get("X-CSRF-Token")
    if not header_token or header_token != csrf_token:
        raise HTTPException(status_code=403, detail="CSRF validation failed")
```

### Cookie configuration

```python
response.set_cookie(
    key="csrf_token",
    value=signed_token,
    httponly=True,
    secure=True,
    samesite="strict",
    max_age=3600,
    path="/",
)
```

A token retrieval endpoint (`GET /csrf-token`) returns the current token for authorized clients so they can include it in `X-CSRF-Token` for protected state-changing operations.

## 3. Clickjacking Fix

### Headers added

A security headers middleware sets the following headers on every response:

- `X-Frame-Options: DENY`
- `Content-Security-Policy: frame-ancestors 'none'`
- `X-Content-Type-Options: nosniff`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), microphone=(), camera=()`

### CSP policy explanation

The policy `frame-ancestors 'none'` blocks the API UI and responses from being embedded in frames or iframes on any origin, which mitigates clickjacking overlays. Combined with `X-Frame-Options: DENY`, this provides defense-in-depth across modern and legacy browser handling.

### How it is tested

`tests/test_clickjacking.py` validates header presence and confirms the CSP contains `frame-ancestors 'none'` on API responses.
