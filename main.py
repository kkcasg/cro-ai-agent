
"""
CRO AI Agent - FastAPI Main Application
========================================

Main entry point for the CRO AI Agent backend application.
Includes middleware, routing, observability, and security configurations.
"""

import asyncio
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from typing import Any, Dict

import structlog
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from opentelemetry import trace
from opentelemetry.exporter.prometheus import PrometheusMetricsExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import Counter, Histogram, generate_latest
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

# Local imports
from app.core.config import get_settings
from app.core.database import engine, get_db
from app.core.logging import setup_logging
from app.core.security import get_current_user
from app.api.v1.api import api_router
from app.agents.router import AgentRouter
from app.integrations.manager import IntegrationManager
from app.rag.manager import RAGManager
from app.services.health import HealthService
from app.utils.exceptions import (
    CROAIException,
    ValidationException,
    AuthenticationException,
    AuthorizationException,
    IntegrationException,
    AIProviderException,
)

# Get settings
settings = get_settings()

# Setup structured logging
setup_logging()
logger = structlog.get_logger(__name__)

# Metrics
REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status_code"]
)

REQUEST_DURATION = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"]
)

AI_REQUESTS = Counter(
    "ai_requests_total",
    "Total AI provider requests",
    ["provider", "model", "status"]
)

AI_COSTS = Counter(
    "ai_costs_total_usd",
    "Total AI costs in USD",
    ["provider", "model"]
)

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

# Global managers
integration_manager: IntegrationManager = None
rag_manager: RAGManager = None
agent_router: AgentRouter = None
health_service: HealthService = None


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware for collecting request metrics."""
    
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        # Get endpoint info
        method = request.method
        path = request.url.path
        
        try:
            response = await call_next(request)
            status_code = response.status_code
            
            # Record metrics
            REQUEST_COUNT.labels(
                method=method,
                endpoint=path,
                status_code=status_code
            ).inc()
            
            duration = time.time() - start_time
            REQUEST_DURATION.labels(
                method=method,
                endpoint=path
            ).observe(duration)
            
            return response
            
        except Exception as e:
            # Record error metrics
            REQUEST_COUNT.labels(
                method=method,
                endpoint=path,
                status_code=500
            ).inc()
            
            duration = time.time() - start_time
            REQUEST_DURATION.labels(
                method=method,
                endpoint=path
            ).observe(duration)
            
            raise e


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware for adding security headers."""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        if settings.SECURITY_HEADERS_ENABLED:
            # Security headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
            
            if settings.FORCE_HTTPS:
                response.headers["Strict-Transport-Security"] = f"max-age={settings.HSTS_MAX_AGE}; includeSubDomains"
        
        return response


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for structured request logging."""
    
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        # Generate trace ID
        trace_id = trace.get_current_span().get_span_context().trace_id
        
        # Log request
        logger.info(
            "Request started",
            method=request.method,
            path=request.url.path,
            query_params=str(request.query_params),
            client_ip=get_remote_address(request),
            trace_id=trace_id,
            user_agent=request.headers.get("user-agent", ""),
        )
        
        try:
            response = await call_next(request)
            
            duration = time.time() - start_time
            
            # Log response
            logger.info(
                "Request completed",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_seconds=duration,
                trace_id=trace_id,
            )
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            
            # Log error
            logger.error(
                "Request failed",
                method=request.method,
                path=request.url.path,
                duration_seconds=duration,
                trace_id=trace_id,
                error=str(e),
                error_type=type(e).__name__,
            )
            
            raise e


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global integration_manager, rag_manager, agent_router, health_service
    
    logger.info("Starting CRO AI Agent application...")
    
    try:
        # Initialize database
        logger.info("Initializing database connection...")
        # Database initialization will be handled by dependency injection
        
        # Initialize RAG manager
        logger.info("Initializing RAG manager...")
        rag_manager = RAGManager()
        await rag_manager.initialize()
        
        # Initialize integration manager
        logger.info("Initializing integration manager...")
        integration_manager = IntegrationManager()
        await integration_manager.initialize()
        
        # Initialize agent router
        logger.info("Initializing agent router...")
        agent_router = AgentRouter(
            integration_manager=integration_manager,
            rag_manager=rag_manager
        )
        await agent_router.initialize()
        
        # Initialize health service
        logger.info("Initializing health service...")
        health_service = HealthService(
            integration_manager=integration_manager,
            rag_manager=rag_manager,
            agent_router=agent_router
        )
        
        # Store managers in app state
        app.state.integration_manager = integration_manager
        app.state.rag_manager = rag_manager
        app.state.agent_router = agent_router
        app.state.health_service = health_service
        
        logger.info("Application startup completed successfully")
        
        yield
        
    except Exception as e:
        logger.error("Failed to start application", error=str(e))
        raise e
    
    finally:
        # Cleanup
        logger.info("Shutting down CRO AI Agent application...")
        
        if agent_router:
            await agent_router.shutdown()
        
        if integration_manager:
            await integration_manager.shutdown()
        
        if rag_manager:
            await rag_manager.shutdown()
        
        logger.info("Application shutdown completed")


def setup_observability():
    """Setup OpenTelemetry and Prometheus monitoring."""
    if not settings.METRICS_ENABLED:
        return
    
    # Setup tracing
    trace.set_tracer_provider(TracerProvider())
    tracer = trace.get_tracer(__name__)
    
    # Setup metrics
    prometheus_exporter = PrometheusMetricsExporter(port=settings.PROMETHEUS_PORT)
    reader = PeriodicExportingMetricReader(prometheus_exporter, export_interval_millis=5000)
    provider = MeterProvider(metric_readers=[reader])
    
    # Instrument FastAPI
    FastAPIInstrumentor.instrument_app(app, tracer_provider=trace.get_tracer_provider())
    
    # Instrument SQLAlchemy
    SQLAlchemyInstrumentor().instrument(engine=engine)
    
    # Instrument Redis
    RedisInstrumentor().instrument()


def create_application() -> FastAPI:
    """Create and configure FastAPI application."""
    
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="CRO AI Agent - Autonomous Chief Revenue Officer with AI",
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
        openapi_url="/openapi.json" if settings.DEBUG else None,
        lifespan=lifespan,
    )
    
    # Setup observability
    setup_observability()
    
    # Add middleware (order matters!)
    
    # 1. Security headers
    app.add_middleware(SecurityHeadersMiddleware)
    
    # 2. CORS
    if settings.CORS_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.CORS_ORIGINS.split(","),
            allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    
    # 3. Trusted hosts
    if not settings.DEBUG:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=[settings.COMPANY_DOMAIN, "localhost", "127.0.0.1"]
        )
    
    # 4. Session middleware
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.SECRET_KEY,
        max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    
    # 5. Rate limiting
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)
    
    # 6. Compression
    if settings.GZIP_COMPRESSION:
        app.add_middleware(GZipMiddleware, minimum_size=1000)
    
    # 7. Metrics collection
    app.add_middleware(MetricsMiddleware)
    
    # 8. Logging
    app.add_middleware(LoggingMiddleware)
    
    return app


# Create application instance
app = create_application()


# Exception handlers
@app.exception_handler(CROAIException)
async def cro_ai_exception_handler(request: Request, exc: CROAIException):
    """Handle custom CRO AI exceptions."""
    logger.error(
        "CRO AI Exception",
        error=str(exc),
        error_code=exc.error_code,
        path=request.url.path,
        method=request.method,
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.error_code,
            "message": exc.message,
            "details": exc.details,
            "timestamp": time.time(),
        }
    )


@app.exception_handler(ValidationException)
async def validation_exception_handler(request: Request, exc: ValidationException):
    """Handle validation exceptions."""
    logger.warning(
        "Validation error",
        error=str(exc),
        path=request.url.path,
        method=request.method,
    )
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "validation_error",
            "message": "Invalid input data",
            "details": exc.details,
            "timestamp": time.time(),
        }
    )


@app.exception_handler(AuthenticationException)
async def authentication_exception_handler(request: Request, exc: AuthenticationException):
    """Handle authentication exceptions."""
    logger.warning(
        "Authentication error",
        error=str(exc),
        path=request.url.path,
        method=request.method,
    )
    
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "error": "authentication_error",
            "message": "Authentication required",
            "details": exc.details,
            "timestamp": time.time(),
        },
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.exception_handler(AuthorizationException)
async def authorization_exception_handler(request: Request, exc: AuthorizationException):
    """Handle authorization exceptions."""
    logger.warning(
        "Authorization error",
        error=str(exc),
        path=request.url.path,
        method=request.method,
    )
    
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={
            "error": "authorization_error",
            "message": "Insufficient permissions",
            "details": exc.details,
            "timestamp": time.time(),
        }
    )


@app.exception_handler(IntegrationException)
async def integration_exception_handler(request: Request, exc: IntegrationException):
    """Handle integration exceptions."""
    logger.error(
        "Integration error",
        error=str(exc),
        integration=exc.integration,
        path=request.url.path,
        method=request.method,
    )
    
    return JSONResponse(
        status_code=status.HTTP_502_BAD_GATEWAY,
        content={
            "error": "integration_error",
            "message": f"Integration error: {exc.integration}",
            "details": exc.details,
            "timestamp": time.time(),
        }
    )


@app.exception_handler(AIProviderException)
async def ai_provider_exception_handler(request: Request, exc: AIProviderException):
    """Handle AI provider exceptions."""
    logger.error(
        "AI provider error",
        error=str(exc),
        provider=exc.provider,
        model=exc.model,
        path=request.url.path,
        method=request.method,
    )
    
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "error": "ai_provider_error",
            "message": f"AI provider error: {exc.provider}",
            "details": exc.details,
            "timestamp": time.time(),
        }
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """Handle FastAPI validation errors."""
    logger.warning(
        "Request validation error",
        error=str(exc),
        path=request.url.path,
        method=request.method,
    )
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "validation_error",
            "message": "Invalid request data",
            "details": exc.errors(),
            "timestamp": time.time(),
        }
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions."""
    logger.warning(
        "HTTP exception",
        status_code=exc.status_code,
        detail=exc.detail,
        path=request.url.path,
        method=request.method,
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "http_error",
            "message": exc.detail,
            "timestamp": time.time(),
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    logger.error(
        "Unexpected error",
        error=str(exc),
        error_type=type(exc).__name__,
        path=request.url.path,
        method=request.method,
        exc_info=True,
    )
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "internal_server_error",
            "message": "An unexpected error occurred",
            "timestamp": time.time(),
        }
    )


# Health check endpoints
@app.get("/health", tags=["Health"])
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
    }


@app.get("/health/detailed", tags=["Health"])
async def detailed_health_check():
    """Detailed health check with component status."""
    if not health_service:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "message": "Health service not initialized",
                "timestamp": time.time(),
            }
        )
    
    health_status = await health_service.check_health()
    
    status_code = (
        status.HTTP_200_OK 
        if health_status["status"] == "healthy" 
        else status.HTTP_503_SERVICE_UNAVAILABLE
    )
    
    return JSONResponse(
        status_code=status_code,
        content=health_status
    )


@app.get("/metrics", tags=["Monitoring"])
async def metrics():
    """Prometheus metrics endpoint."""
    if not settings.METRICS_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Metrics not enabled"
        )
    
    return Response(
        content=generate_latest(),
        media_type="text/plain"
    )


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information."""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "description": "CRO AI Agent - Autonomous Chief Revenue Officer with AI",
        "company": settings.COMPANY_NAME,
        "domain": settings.COMPANY_DOMAIN,
        "environment": settings.ENVIRONMENT,
        "docs_url": "/docs" if settings.DEBUG else None,
        "health_url": "/health",
        "timestamp": time.time(),
    }


# Include API routes
app.include_router(api_router, prefix="/api/v1")


# Agent chat endpoint
@app.post("/chat", tags=["Agent"])
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def chat_with_agent(
    request: Request,
    message: str,
    user_id: str = None,
    session_id: str = None,
    current_user: dict = Depends(get_current_user)
):
    """Chat with the CRO AI Agent."""
    if not agent_router:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Agent router not initialized"
        )
    
    try:
        response = await agent_router.process_message(
            message=message,
            user_id=user_id or current_user.get("id"),
            session_id=session_id,
            context={
                "user": current_user,
                "request_id": request.headers.get("x-request-id"),
                "client_ip": get_remote_address(request),
            }
        )
        
        return response
        
    except Exception as e:
        logger.error(
            "Agent chat error",
            error=str(e),
            message=message,
            user_id=user_id,
            session_id=session_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process message"
        )


if __name__ == "__main__":
    # Development server
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.RELOAD,
        workers=settings.WORKERS if not settings.RELOAD else 1,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=True,
        use_colors=True,
    )
