
"""
CRO AI Agent - Security and Authentication System
=================================================

Complete security system with JWT authentication, password hashing,
rate limiting, CORS, input validation, and security middleware.
"""

import hashlib
import hmac
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Dict, List, Optional, Union, Callable
from urllib.parse import urlparse

import bcrypt
import jwt
from fastapi import HTTPException, Request, Response, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from pydantic import BaseModel, validator
import structlog

from app.core.config import get_security_settings, get_settings

# Get settings
settings = get_settings()
security_settings = get_security_settings()

# Setup logger
logger = structlog.get_logger(__name__)

# Password context for hashing
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=security_settings.BCRYPT_ROUNDS,
)

# JWT Bearer scheme
bearer_scheme = HTTPBearer(auto_error=False)

# Rate limiting storage (in production, use Redis)
rate_limit_storage: Dict[str, Dict[str, Any]] = {}

# Security headers
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}

if security_settings.HSTS_MAX_AGE > 0:
    SECURITY_HEADERS["Strict-Transport-Security"] = f"max-age={security_settings.HSTS_MAX_AGE}; includeSubDomains"


class TokenData(BaseModel):
    """Token data model."""
    user_id: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    roles: List[str] = []
    permissions: List[str] = []
    exp: Optional[datetime] = None
    iat: Optional[datetime] = None
    jti: Optional[str] = None  # JWT ID for token revocation


class SecurityException(HTTPException):
    """Custom security exception."""
    
    def __init__(self, detail: str, status_code: int = status.HTTP_401_UNAUTHORIZED):
        super().__init__(status_code=status_code, detail=detail)


class RateLimitExceeded(SecurityException):
    """Rate limit exceeded exception."""
    
    def __init__(self, detail: str = "Rate limit exceeded"):
        super().__init__(detail=detail, status_code=status.HTTP_429_TOO_MANY_REQUESTS)


class InvalidToken(SecurityException):
    """Invalid token exception."""
    
    def __init__(self, detail: str = "Invalid token"):
        super().__init__(detail=detail, status_code=status.HTTP_401_UNAUTHORIZED)


class InsufficientPermissions(SecurityException):
    """Insufficient permissions exception."""
    
    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(detail=detail, status_code=status.HTTP_403_FORBIDDEN)


# Password utilities
def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.
    
    Args:
        password: Plain text password
        
    Returns:
        Hashed password
    """
    try:
        return pwd_context.hash(password)
    except Exception as e:
        logger.error("Failed to hash password", error=str(e))
        raise SecurityException("Failed to process password")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.
    
    Args:
        plain_password: Plain text password
        hashed_password: Hashed password
        
    Returns:
        True if password matches, False otherwise
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error("Failed to verify password", error=str(e))
        return False


def generate_password(length: int = 12) -> str:
    """
    Generate a secure random password.
    
    Args:
        length: Password length
        
    Returns:
        Generated password
    """
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def validate_password_strength(password: str) -> Dict[str, Any]:
    """
    Validate password strength.
    
    Args:
        password: Password to validate
        
    Returns:
        Dictionary with validation results
    """
    result = {
        "valid": True,
        "score": 0,
        "issues": [],
        "suggestions": []
    }
    
    # Length check
    if len(password) < 8:
        result["valid"] = False
        result["issues"].append("Password must be at least 8 characters long")
    else:
        result["score"] += 1
    
    # Character variety checks
    if not re.search(r"[a-z]", password):
        result["issues"].append("Password should contain lowercase letters")
    else:
        result["score"] += 1
    
    if not re.search(r"[A-Z]", password):
        result["issues"].append("Password should contain uppercase letters")
    else:
        result["score"] += 1
    
    if not re.search(r"\d", password):
        result["issues"].append("Password should contain numbers")
    else:
        result["score"] += 1
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        result["issues"].append("Password should contain special characters")
    else:
        result["score"] += 1
    
    # Common patterns
    if re.search(r"(.)\1{2,}", password):
        result["issues"].append("Password should not contain repeated characters")
        result["score"] -= 1
    
    if re.search(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde)", password.lower()):
        result["issues"].append("Password should not contain sequential characters")
        result["score"] -= 1
    
    # Set final validity
    if result["score"] < 3:
        result["valid"] = False
    
    return result


# JWT utilities
def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Data to encode in token
        expires_delta: Token expiration time
        
    Returns:
        Encoded JWT token
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=security_settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        )
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": secrets.token_urlsafe(16),  # JWT ID for revocation
    })
    
    try:
        encoded_jwt = jwt.encode(
            to_encode,
            security_settings.JWT_SECRET_KEY,
            algorithm=security_settings.JWT_ALGORITHM
        )
        
        logger.debug(
            "Access token created",
            user_id=data.get("user_id"),
            expires_at=expire.isoformat(),
        )
        
        return encoded_jwt
    
    except Exception as e:
        logger.error("Failed to create access token", error=str(e))
        raise SecurityException("Failed to create token")


def create_refresh_token(user_id: str) -> str:
    """
    Create a JWT refresh token.
    
    Args:
        user_id: User ID
        
    Returns:
        Encoded JWT refresh token
    """
    expire = datetime.now(timezone.utc) + timedelta(
        days=security_settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
    )
    
    to_encode = {
        "user_id": user_id,
        "type": "refresh",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": secrets.token_urlsafe(16),
    }
    
    try:
        encoded_jwt = jwt.encode(
            to_encode,
            security_settings.JWT_SECRET_KEY,
            algorithm=security_settings.JWT_ALGORITHM
        )
        
        logger.debug(
            "Refresh token created",
            user_id=user_id,
            expires_at=expire.isoformat(),
        )
        
        return encoded_jwt
    
    except Exception as e:
        logger.error("Failed to create refresh token", error=str(e))
        raise SecurityException("Failed to create refresh token")


def verify_token(token: str) -> TokenData:
    """
    Verify and decode a JWT token.
    
    Args:
        token: JWT token to verify
        
    Returns:
        Decoded token data
        
    Raises:
        InvalidToken: If token is invalid or expired
    """
    try:
        payload = jwt.decode(
            token,
            security_settings.JWT_SECRET_KEY,
            algorithms=[security_settings.JWT_ALGORITHM]
        )
        
        # Check if token is expired
        exp = payload.get("exp")
        if exp and datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
            raise InvalidToken("Token has expired")
        
        # Create token data
        token_data = TokenData(
            user_id=payload.get("user_id"),
            username=payload.get("username"),
            email=payload.get("email"),
            roles=payload.get("roles", []),
            permissions=payload.get("permissions", []),
            exp=datetime.fromtimestamp(exp, tz=timezone.utc) if exp else None,
            iat=datetime.fromtimestamp(payload.get("iat"), tz=timezone.utc) if payload.get("iat") else None,
            jti=payload.get("jti"),
        )
        
        logger.debug(
            "Token verified successfully",
            user_id=token_data.user_id,
            jti=token_data.jti,
        )
        
        return token_data
    
    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        raise InvalidToken("Token has expired")
    
    except jwt.InvalidTokenError as e:
        logger.warning("Invalid token", error=str(e))
        raise InvalidToken("Invalid token")
    
    except Exception as e:
        logger.error("Failed to verify token", error=str(e))
        raise InvalidToken("Token verification failed")


# Input validation and sanitization
def sanitize_input(value: str, max_length: int = 1000) -> str:
    """
    Sanitize user input to prevent injection attacks.
    
    Args:
        value: Input value to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized input
    """
    if not isinstance(value, str):
        value = str(value)
    
    # Truncate if too long
    if len(value) > max_length:
        value = value[:max_length]
    
    # Remove null bytes
    value = value.replace('\x00', '')
    
    # Remove control characters except newlines and tabs
    value = re.sub(r'[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]', '', value)
    
    # Basic HTML/script tag removal
    value = re.sub(r'<script[^>]*>.*?</script>', '', value, flags=re.IGNORECASE | re.DOTALL)
    value = re.sub(r'<[^>]+>', '', value)
    
    # Remove potential SQL injection patterns
    sql_patterns = [
        r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)',
        r'(--|#|/\*|\*/)',
        r'(\bOR\b.*=.*\bOR\b)',
        r'(\bAND\b.*=.*\bAND\b)',
    ]
    
    for pattern in sql_patterns:
        value = re.sub(pattern, '', value, flags=re.IGNORECASE)
    
    return value.strip()


def validate_email(email: str) -> bool:
    """
    Validate email format.
    
    Args:
        email: Email to validate
        
    Returns:
        True if valid, False otherwise
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_url(url: str, allowed_schemes: List[str] = None) -> bool:
    """
    Validate URL format and scheme.
    
    Args:
        url: URL to validate
        allowed_schemes: List of allowed schemes (default: ['http', 'https'])
        
    Returns:
        True if valid, False otherwise
    """
    if allowed_schemes is None:
        allowed_schemes = ['http', 'https']
    
    try:
        parsed = urlparse(url)
        return (
            parsed.scheme in allowed_schemes and
            parsed.netloc and
            len(url) <= 2048  # Reasonable URL length limit
        )
    except Exception:
        return False


# Rate limiting
def get_client_ip(request: Request) -> str:
    """
    Get client IP address from request.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Client IP address
    """
    # Check for forwarded headers (when behind proxy)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    # Fallback to direct connection
    return request.client.host if request.client else "unknown"


def is_rate_limited(
    identifier: str,
    limit: int = None,
    window: int = 60,
    burst: int = None
) -> bool:
    """
    Check if identifier is rate limited.
    
    Args:
        identifier: Unique identifier (IP, user ID, etc.)
        limit: Requests per window (default from settings)
        window: Time window in seconds
        burst: Burst limit (default from settings)
        
    Returns:
        True if rate limited, False otherwise
    """
    if limit is None:
        limit = security_settings.RATE_LIMIT_PER_MINUTE
    
    if burst is None:
        burst = security_settings.RATE_LIMIT_BURST
    
    current_time = time.time()
    
    # Clean old entries
    if identifier in rate_limit_storage:
        rate_limit_storage[identifier]["requests"] = [
            req_time for req_time in rate_limit_storage[identifier]["requests"]
            if current_time - req_time < window
        ]
    else:
        rate_limit_storage[identifier] = {"requests": []}
    
    requests = rate_limit_storage[identifier]["requests"]
    
    # Check burst limit
    if len(requests) >= burst:
        return True
    
    # Check rate limit
    if len(requests) >= limit:
        return True
    
    # Add current request
    requests.append(current_time)
    
    return False


# Security middleware
async def security_headers_middleware(request: Request, call_next):
    """
    Add security headers to responses.
    
    Args:
        request: FastAPI request
        call_next: Next middleware function
        
    Returns:
        Response with security headers
    """
    response = await call_next(request)
    
    if security_settings.SECURITY_HEADERS_ENABLED:
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
    
    return response


async def rate_limit_middleware(request: Request, call_next):
    """
    Rate limiting middleware.
    
    Args:
        request: FastAPI request
        call_next: Next middleware function
        
    Returns:
        Response or rate limit error
    """
    client_ip = get_client_ip(request)
    
    if is_rate_limited(client_ip):
        logger.warning(
            "Rate limit exceeded",
            client_ip=client_ip,
            path=request.url.path,
            method=request.method,
        )
        raise RateLimitExceeded()
    
    return await call_next(request)


async def cors_middleware(request: Request, call_next):
    """
    CORS middleware.
    
    Args:
        request: FastAPI request
        call_next: Next middleware function
        
    Returns:
        Response with CORS headers
    """
    response = await call_next(request)
    
    # Get allowed origins
    allowed_origins = security_settings.CORS_ORIGINS.split(",")
    origin = request.headers.get("origin")
    
    if origin and origin in allowed_origins:
        response.headers["Access-Control-Allow-Origin"] = origin
    elif "*" in allowed_origins:
        response.headers["Access-Control-Allow-Origin"] = "*"
    
    if security_settings.CORS_ALLOW_CREDENTIALS:
        response.headers["Access-Control-Allow-Credentials"] = "true"
    
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
    
    return response


# Authentication dependencies
async def get_current_user_token(
    credentials: Optional[HTTPAuthorizationCredentials] = None
) -> TokenData:
    """
    Get current user from JWT token.
    
    Args:
        credentials: HTTP authorization credentials
        
    Returns:
        Token data
        
    Raises:
        InvalidToken: If token is missing or invalid
    """
    if not credentials:
        raise InvalidToken("Missing authorization token")
    
    if credentials.scheme.lower() != "bearer":
        raise InvalidToken("Invalid authentication scheme")
    
    return verify_token(credentials.credentials)


def require_permissions(*required_permissions: str):
    """
    Decorator to require specific permissions.
    
    Args:
        *required_permissions: Required permissions
        
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get token data from kwargs (injected by FastAPI dependency)
            token_data = kwargs.get("current_user")
            if not token_data:
                raise InsufficientPermissions("Authentication required")
            
            # Check permissions
            user_permissions = set(token_data.permissions)
            required_perms = set(required_permissions)
            
            if not required_perms.issubset(user_permissions):
                missing_perms = required_perms - user_permissions
                logger.warning(
                    "Insufficient permissions",
                    user_id=token_data.user_id,
                    required_permissions=list(required_perms),
                    user_permissions=list(user_permissions),
                    missing_permissions=list(missing_perms),
                )
                raise InsufficientPermissions(
                    f"Missing permissions: {', '.join(missing_perms)}"
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_roles(*required_roles: str):
    """
    Decorator to require specific roles.
    
    Args:
        *required_roles: Required roles
        
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get token data from kwargs (injected by FastAPI dependency)
            token_data = kwargs.get("current_user")
            if not token_data:
                raise InsufficientPermissions("Authentication required")
            
            # Check roles
            user_roles = set(token_data.roles)
            required_role_set = set(required_roles)
            
            if not required_role_set.intersection(user_roles):
                logger.warning(
                    "Insufficient roles",
                    user_id=token_data.user_id,
                    required_roles=list(required_role_set),
                    user_roles=list(user_roles),
                )
                raise InsufficientPermissions(
                    f"Required roles: {', '.join(required_roles)}"
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


# Cryptographic utilities
def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.
    
    Args:
        length: Token length in bytes
        
    Returns:
        URL-safe base64 encoded token
    """
    return secrets.token_urlsafe(length)


def constant_time_compare(a: str, b: str) -> bool:
    """
    Compare two strings in constant time to prevent timing attacks.
    
    Args:
        a: First string
        b: Second string
        
    Returns:
        True if strings are equal, False otherwise
    """
    return hmac.compare_digest(a.encode(), b.encode())


def hash_api_key(api_key: str) -> str:
    """
    Hash an API key for secure storage.
    
    Args:
        api_key: API key to hash
        
    Returns:
        Hashed API key
    """
    return hashlib.sha256(api_key.encode()).hexdigest()


# Security audit logging
def log_security_event(
    event_type: str,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
):
    """
    Log security-related events for audit purposes.
    
    Args:
        event_type: Type of security event
        user_id: User ID if applicable
        ip_address: Client IP address
        details: Additional event details
    """
    logger.info(
        f"Security event: {event_type}",
        event_type=event_type,
        user_id=user_id,
        ip_address=ip_address,
        details=details or {},
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


# Export commonly used items
__all__ = [
    # Password utilities
    "hash_password",
    "verify_password",
    "generate_password",
    "validate_password_strength",
    
    # JWT utilities
    "create_access_token",
    "create_refresh_token",
    "verify_token",
    "TokenData",
    
    # Input validation
    "sanitize_input",
    "validate_email",
    "validate_url",
    
    # Rate limiting
    "get_client_ip",
    "is_rate_limited",
    
    # Middleware
    "security_headers_middleware",
    "rate_limit_middleware",
    "cors_middleware",
    
    # Authentication
    "get_current_user_token",
    "require_permissions",
    "require_roles",
    
    # Cryptographic utilities
    "generate_secure_token",
    "constant_time_compare",
    "hash_api_key",
    
    # Exceptions
    "SecurityException",
    "RateLimitExceeded",
    "InvalidToken",
    "InsufficientPermissions",
    
    # Audit logging
    "log_security_event",
    
    # Bearer scheme
    "bearer_scheme",
]
