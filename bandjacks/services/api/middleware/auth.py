"""JWT/OIDC authentication middleware with feature flag support."""

import logging
import os
from typing import Optional, Dict, Any, List
from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import jwt
import httpx
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)

# Feature flag for authentication
ENABLE_AUTH = os.getenv("ENABLE_AUTH", "false").lower() == "true"
OIDC_ISSUER = os.getenv("OIDC_ISSUER", "")
OIDC_AUDIENCE = os.getenv("OIDC_AUDIENCE", "bandjacks-api")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "RS256")
JWKS_URL = f"{OIDC_ISSUER}/.well-known/jwks.json" if OIDC_ISSUER else ""

# Role definitions
WRITE_OPERATIONS = ["POST", "PUT", "PATCH", "DELETE"]
READ_OPERATIONS = ["GET", "HEAD", "OPTIONS"]

# Exempt paths that don't require auth
EXEMPT_PATHS = [
    "/docs",
    "/redoc",
    "/openapi.json",
    "/health",
    "/v1/catalog",  # Public catalog endpoints
]


class JWTAuthMiddleware(BaseHTTPMiddleware):
    """JWT authentication middleware with OIDC support."""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.jwks_cache = None
        self.jwks_cache_time = None
        self.cache_duration = timedelta(hours=1)
    
    async def dispatch(self, request: Request, call_next):
        """Process request with authentication check."""
        
        # Skip auth if disabled
        if not ENABLE_AUTH:
            response = await call_next(request)
            return response
        
        # Check if path is exempt
        path = request.url.path
        if any(path.startswith(exempt) for exempt in EXEMPT_PATHS):
            response = await call_next(request)
            return response
        
        # Check if operation requires auth (only writes by default)
        if request.method not in WRITE_OPERATIONS:
            # Read operations allowed without auth unless configured otherwise
            if os.getenv("REQUIRE_AUTH_FOR_READS", "false").lower() != "true":
                response = await call_next(request)
                return response
        
        # Extract and verify token
        try:
            token = self._extract_token(request)
            if not token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authorization header missing",
                    headers={"WWW-Authenticate": "Bearer"}
                )
            
            # Verify token
            payload = await self._verify_token(token)
            
            # Add user info to request state
            request.state.user = {
                "sub": payload.get("sub"),
                "email": payload.get("email"),
                "name": payload.get("name"),
                "roles": payload.get("roles", []),
                "scopes": payload.get("scope", "").split() if payload.get("scope") else []
            }
            
            # Check authorization for write operations
            if request.method in WRITE_OPERATIONS:
                self._check_write_permission(request.state.user, path)
            
            response = await call_next(request)
            return response
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"}
            )
    
    def _extract_token(self, request: Request) -> Optional[str]:
        """Extract JWT token from request headers."""
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return None
        
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None
        
        return parts[1]
    
    async def _verify_token(self, token: str) -> Dict[str, Any]:
        """Verify JWT token with OIDC provider."""
        
        # If using OIDC, get JWKS
        if OIDC_ISSUER and JWT_ALGORITHM.startswith("RS"):
            jwks = await self._get_jwks()
            
            # Decode token header to get kid
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            
            # Find matching key
            key = None
            for jwk in jwks.get("keys", []):
                if jwk.get("kid") == kid:
                    key = self._jwk_to_pem(jwk)
                    break
            
            if not key:
                raise ValueError("Unable to find matching key")
            
            # Verify token
            payload = jwt.decode(
                token,
                key,
                algorithms=[JWT_ALGORITHM],
                audience=OIDC_AUDIENCE,
                issuer=OIDC_ISSUER
            )
        else:
            # Use symmetric key for local development
            secret = os.getenv("JWT_SECRET", "development-secret")
            payload = jwt.decode(
                token,
                secret,
                algorithms=["HS256"]
            )
        
        # Check expiration
        exp = payload.get("exp")
        if exp and datetime.utcfromtimestamp(exp) < datetime.utcnow():
            raise ValueError("Token expired")
        
        return payload
    
    async def _get_jwks(self) -> Dict[str, Any]:
        """Get JWKS from OIDC provider with caching."""
        
        # Check cache
        if self.jwks_cache and self.jwks_cache_time:
            if datetime.utcnow() - self.jwks_cache_time < self.cache_duration:
                return self.jwks_cache
        
        # Fetch JWKS
        async with httpx.AsyncClient() as client:
            response = await client.get(JWKS_URL)
            response.raise_for_status()
            jwks = response.json()
        
        # Update cache
        self.jwks_cache = jwks
        self.jwks_cache_time = datetime.utcnow()
        
        return jwks
    
    def _jwk_to_pem(self, jwk: Dict[str, Any]) -> str:
        """Convert JWK to PEM format for RS256 verification."""
        import base64
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from cryptography.hazmat.backends import default_backend

        def _b64url_decode(data: str) -> bytes:
            padding = 4 - len(data) % 4
            return base64.urlsafe_b64decode(data + "=" * padding)

        n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        public_key = RSAPublicNumbers(e, n).public_key(default_backend())
        return public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
    
    def _check_write_permission(self, user: Dict[str, Any], path: str):
        """Check if user has permission for write operations."""
        
        # Check for admin role
        if "admin" in user.get("roles", []):
            return
        
        # Check for write scope
        if "write" in user.get("scopes", []):
            return
        
        # Check specific path permissions
        allowed_write_paths = {
            "/v1/feedback": ["analyst", "reviewer"],
            "/v1/review": ["reviewer", "admin"],
            "/v1/candidates": ["analyst", "admin"],
        }
        
        for allowed_path, allowed_roles in allowed_write_paths.items():
            if path.startswith(allowed_path):
                if any(role in user.get("roles", []) for role in allowed_roles):
                    return
        
        # No permission
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions for this operation"
        )


# Security scheme for FastAPI docs
security = HTTPBearer(auto_error=False)


def get_current_user(request: Request) -> Optional[Dict[str, Any]]:
    """Get current authenticated user from request."""
    if not ENABLE_AUTH:
        return {"sub": "anonymous", "roles": ["admin"]}
    
    return getattr(request.state, "user", None)


def require_roles(*roles: str):
    """Decorator to require specific roles."""
    def decorator(func):
        async def wrapper(request: Request, *args, **kwargs):
            user = get_current_user(request)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated"
                )
            
            user_roles = user.get("roles", [])
            if not any(role in user_roles for role in roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Required roles: {roles}"
                )
            
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator