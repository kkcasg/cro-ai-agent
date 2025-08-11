
"""
CRO AI Agent - Database Configuration
====================================

SQLAlchemy configuration for PostgreSQL with connection pooling,
session management, and FastAPI dependency injection.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

import structlog
from sqlalchemy import (
    create_engine,
    event,
    pool,
    text,
    MetaData,
    inspect,
)
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
    AsyncEngine,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import (
    Session,
    sessionmaker,
    DeclarativeBase,
)
from sqlalchemy.pool import QueuePool
from sqlalchemy.exc import SQLAlchemyError, DisconnectionError
from sqlalchemy.sql import func

from app.core.config import get_database_settings, get_settings

# Get settings
settings = get_settings()
db_settings = get_database_settings()

# Setup logger
logger = structlog.get_logger(__name__)

# Metadata with naming convention for constraints
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

metadata = MetaData(naming_convention=convention)


class Base(DeclarativeBase):
    """Base class for all database models."""
    metadata = metadata
    
    def __repr__(self):
        """String representation of model instances."""
        class_name = self.__class__.__name__
        attrs = []
        
        # Get primary key columns
        mapper = inspect(self.__class__)
        for column in mapper.primary_key:
            value = getattr(self, column.name, None)
            attrs.append(f"{column.name}={value}")
        
        return f"<{class_name}({', '.join(attrs)})>"


# Database engines
engine: Optional[AsyncEngine] = None
sync_engine = None

# Session factories
AsyncSessionLocal: Optional[async_sessionmaker[AsyncSession]] = None
SessionLocal: Optional[sessionmaker[Session]] = None


def create_database_engines():
    """Create database engines with proper configuration."""
    global engine, sync_engine, AsyncSessionLocal, SessionLocal
    
    # Connection pool settings
    pool_settings = {
        "poolclass": QueuePool,
        "pool_size": db_settings.DATABASE_POOL_SIZE,
        "max_overflow": db_settings.DATABASE_MAX_OVERFLOW,
        "pool_timeout": db_settings.DATABASE_POOL_TIMEOUT,
        "pool_recycle": 3600,  # Recycle connections every hour
        "pool_pre_ping": True,  # Validate connections before use
    }
    
    # Engine settings
    engine_settings = {
        "echo": settings.development.SQLALCHEMY_ECHO,
        "echo_pool": settings.DEBUG and settings.development.SHOW_SQL_QUERIES,
        "future": True,
        "connect_args": {
            "sslmode": db_settings.DATABASE_SSL_MODE,
            "application_name": f"{settings.APP_NAME}-{settings.ENVIRONMENT}",
            "connect_timeout": 10,
            "command_timeout": 30,
        }
    }
    
    try:
        # Create async engine
        async_url = str(db_settings.DATABASE_URL).replace("postgresql://", "postgresql+asyncpg://")
        engine = create_async_engine(
            async_url,
            **pool_settings,
            **engine_settings,
        )
        
        # Create sync engine for migrations and admin tasks
        sync_engine = create_engine(
            str(db_settings.DATABASE_URL),
            **pool_settings,
            **engine_settings,
        )
        
        # Create session factories
        AsyncSessionLocal = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=True,
            autocommit=False,
        )
        
        SessionLocal = sessionmaker(
            sync_engine,
            autocommit=False,
            autoflush=True,
        )
        
        logger.info(
            "Database engines created successfully",
            database_url=str(db_settings.DATABASE_URL).split("@")[-1],  # Hide credentials
            pool_size=db_settings.DATABASE_POOL_SIZE,
            max_overflow=db_settings.DATABASE_MAX_OVERFLOW,
        )
        
    except Exception as e:
        logger.error(
            "Failed to create database engines",
            error=str(e),
            database_url=str(db_settings.DATABASE_URL).split("@")[-1],
        )
        raise


def setup_engine_events():
    """Setup SQLAlchemy engine events for monitoring and logging."""
    if not engine or not sync_engine:
        return
    
    @event.listens_for(engine.sync_engine, "connect")
    def receive_connect(dbapi_connection, connection_record):
        """Handle new database connections."""
        logger.debug(
            "New database connection established",
            connection_id=id(dbapi_connection),
        )
    
    @event.listens_for(engine.sync_engine, "checkout")
    def receive_checkout(dbapi_connection, connection_record, connection_proxy):
        """Handle connection checkout from pool."""
        logger.debug(
            "Connection checked out from pool",
            connection_id=id(dbapi_connection),
            pool_size=connection_proxy.pool.size(),
            checked_out=connection_proxy.pool.checkedout(),
        )
    
    @event.listens_for(engine.sync_engine, "checkin")
    def receive_checkin(dbapi_connection, connection_record):
        """Handle connection checkin to pool."""
        logger.debug(
            "Connection checked in to pool",
            connection_id=id(dbapi_connection),
        )
    
    @event.listens_for(engine.sync_engine, "invalidate")
    def receive_invalidate(dbapi_connection, connection_record, exception):
        """Handle connection invalidation."""
        logger.warning(
            "Database connection invalidated",
            connection_id=id(dbapi_connection),
            error=str(exception) if exception else None,
        )
    
    @event.listens_for(engine.sync_engine, "soft_invalidate")
    def receive_soft_invalidate(dbapi_connection, connection_record, exception):
        """Handle soft connection invalidation."""
        logger.info(
            "Database connection soft invalidated",
            connection_id=id(dbapi_connection),
            error=str(exception) if exception else None,
        )


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency for getting database session.
    
    Yields:
        AsyncSession: Database session
        
    Raises:
        SQLAlchemyError: If database connection fails
    """
    if not AsyncSessionLocal:
        raise RuntimeError("Database not initialized. Call create_database_engines() first.")
    
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except SQLAlchemyError as e:
            logger.error(
                "Database session error",
                error=str(e),
                error_type=type(e).__name__,
            )
            await session.rollback()
            raise
        except Exception as e:
            logger.error(
                "Unexpected error in database session",
                error=str(e),
                error_type=type(e).__name__,
            )
            await session.rollback()
            raise
        finally:
            await session.close()


def get_sync_db() -> Session:
    """
    Get synchronous database session for migrations and admin tasks.
    
    Returns:
        Session: Synchronous database session
        
    Raises:
        SQLAlchemyError: If database connection fails
    """
    if not SessionLocal:
        raise RuntimeError("Database not initialized. Call create_database_engines() first.")
    
    return SessionLocal()


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Context manager for getting database session outside of FastAPI.
    
    Yields:
        AsyncSession: Database session
        
    Example:
        async with get_db_session() as session:
            result = await session.execute(select(User))
    """
    if not AsyncSessionLocal:
        raise RuntimeError("Database not initialized. Call create_database_engines() first.")
    
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except SQLAlchemyError as e:
            logger.error(
                "Database session error",
                error=str(e),
                error_type=type(e).__name__,
            )
            await session.rollback()
            raise
        except Exception as e:
            logger.error(
                "Unexpected error in database session",
                error=str(e),
                error_type=type(e).__name__,
            )
            await session.rollback()
            raise


async def check_database_connection() -> bool:
    """
    Check if database connection is healthy.
    
    Returns:
        bool: True if connection is healthy, False otherwise
    """
    if not engine:
        logger.error("Database engine not initialized")
        return False
    
    try:
        async with engine.begin() as conn:
            result = await conn.execute(text("SELECT 1"))
            row = result.fetchone()
            
            if row and row[0] == 1:
                logger.debug("Database connection check successful")
                return True
            else:
                logger.error("Database connection check failed: unexpected result")
                return False
                
    except Exception as e:
        logger.error(
            "Database connection check failed",
            error=str(e),
            error_type=type(e).__name__,
        )
        return False


async def get_database_info() -> dict:
    """
    Get database information for health checks and monitoring.
    
    Returns:
        dict: Database information including version, connections, etc.
    """
    if not engine:
        return {"status": "not_initialized"}
    
    try:
        async with engine.begin() as conn:
            # Get PostgreSQL version
            version_result = await conn.execute(text("SELECT version()"))
            version = version_result.scalar()
            
            # Get current database name
            db_result = await conn.execute(text("SELECT current_database()"))
            database_name = db_result.scalar()
            
            # Get connection count
            conn_result = await conn.execute(text("""
                SELECT count(*) 
                FROM pg_stat_activity 
                WHERE datname = current_database()
            """))
            connection_count = conn_result.scalar()
            
            # Get database size
            size_result = await conn.execute(text("""
                SELECT pg_size_pretty(pg_database_size(current_database()))
            """))
            database_size = size_result.scalar()
            
            return {
                "status": "connected",
                "version": version,
                "database_name": database_name,
                "connection_count": connection_count,
                "database_size": database_size,
                "pool_size": engine.pool.size(),
                "checked_out_connections": engine.pool.checkedout(),
                "overflow_connections": engine.pool.overflow(),
                "checked_in_connections": engine.pool.checkedin(),
            }
            
    except Exception as e:
        logger.error(
            "Failed to get database info",
            error=str(e),
            error_type=type(e).__name__,
        )
        return {
            "status": "error",
            "error": str(e),
        }


async def create_tables():
    """Create all database tables."""
    if not engine:
        raise RuntimeError("Database engine not initialized")
    
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        logger.info("Database tables created successfully")
        
    except Exception as e:
        logger.error(
            "Failed to create database tables",
            error=str(e),
            error_type=type(e).__name__,
        )
        raise


async def drop_tables():
    """Drop all database tables. Use with caution!"""
    if not engine:
        raise RuntimeError("Database engine not initialized")
    
    if settings.ENVIRONMENT == "production":
        raise RuntimeError("Cannot drop tables in production environment")
    
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        
        logger.warning("Database tables dropped")
        
    except Exception as e:
        logger.error(
            "Failed to drop database tables",
            error=str(e),
            error_type=type(e).__name__,
        )
        raise


async def reset_database():
    """Reset database by dropping and recreating all tables."""
    if settings.ENVIRONMENT == "production":
        raise RuntimeError("Cannot reset database in production environment")
    
    logger.warning("Resetting database...")
    await drop_tables()
    await create_tables()
    logger.info("Database reset completed")


class DatabaseManager:
    """Database manager for handling connections and operations."""
    
    def __init__(self):
        self.engine = None
        self.session_factory = None
        self._initialized = False
    
    async def initialize(self):
        """Initialize database manager."""
        if self._initialized:
            return
        
        create_database_engines()
        setup_engine_events()
        
        self.engine = engine
        self.session_factory = AsyncSessionLocal
        self._initialized = True
        
        logger.info("Database manager initialized")
    
    async def shutdown(self):
        """Shutdown database manager."""
        if not self._initialized:
            return
        
        if self.engine:
            await self.engine.dispose()
        
        if sync_engine:
            sync_engine.dispose()
        
        self._initialized = False
        logger.info("Database manager shutdown completed")
    
    async def health_check(self) -> dict:
        """Perform database health check."""
        if not self._initialized:
            return {"status": "not_initialized"}
        
        return await get_database_info()
    
    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Context manager for database transactions.
        
        Automatically commits on success or rolls back on error.
        
        Example:
            async with db_manager.transaction() as session:
                user = User(name="John")
                session.add(user)
                # Automatically committed
        """
        if not self.session_factory:
            raise RuntimeError("Database manager not initialized")
        
        async with self.session_factory() as session:
            async with session.begin():
                try:
                    yield session
                except Exception:
                    await session.rollback()
                    raise


# Global database manager instance
db_manager = DatabaseManager()


# Convenience functions
async def init_db():
    """Initialize database."""
    await db_manager.initialize()


async def close_db():
    """Close database connections."""
    await db_manager.shutdown()


# Export commonly used items
__all__ = [
    "Base",
    "engine",
    "sync_engine",
    "AsyncSessionLocal",
    "SessionLocal",
    "get_db",
    "get_sync_db",
    "get_db_session",
    "check_database_connection",
    "get_database_info",
    "create_tables",
    "drop_tables",
    "reset_database",
    "DatabaseManager",
    "db_manager",
    "init_db",
    "close_db",
    "create_database_engines",
    "setup_engine_events",
]
