
"""
CRO AI Agent - Core Configuration Settings
==========================================

Pydantic-based configuration management for environment variables.
Provides type validation, default values, and organized settings.
"""

import os
import secrets
from functools import lru_cache
from typing import Any, Dict, List, Optional, Union

from pydantic import (
    BaseSettings,
    Field,
    validator,
    root_validator,
    AnyHttpUrl,
    EmailStr,
    PostgresDsn,
    RedisDsn,
)
from pydantic.networks import AnyUrl


class DatabaseSettings(BaseSettings):
    """Database configuration settings."""
    
    # PostgreSQL
    DATABASE_URL: Optional[PostgresDsn] = None
    DATABASE_HOST: str = "localhost"
    DATABASE_PORT: int = 5432
    DATABASE_NAME: str = "cro_ai_db"
    DATABASE_USER: str = "cro_user"
    DATABASE_PASSWORD: str = "cro_password"
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20
    DATABASE_POOL_TIMEOUT: int = 30
    DATABASE_SSL_MODE: str = "prefer"
    
    # Test Database
    TEST_DATABASE_URL: Optional[PostgresDsn] = None
    
    @validator("DATABASE_URL", pre=True)
    def assemble_db_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        if isinstance(v, str):
            return v
        return PostgresDsn.build(
            scheme="postgresql",
            user=values.get("DATABASE_USER"),
            password=values.get("DATABASE_PASSWORD"),
            host=values.get("DATABASE_HOST"),
            port=str(values.get("DATABASE_PORT")),
            path=f"/{values.get('DATABASE_NAME') or ''}",
        )
    
    class Config:
        env_prefix = ""
        case_sensitive = True


class RedisSettings(BaseSettings):
    """Redis configuration settings."""
    
    REDIS_URL: Optional[RedisDsn] = None
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: Optional[str] = None
    REDIS_SSL: bool = False
    REDIS_POOL_SIZE: int = 10
    
    # Cache TTL settings
    CACHE_TTL_SHORT: int = 300      # 5 minutes
    CACHE_TTL_MEDIUM: int = 1800    # 30 minutes
    CACHE_TTL_LONG: int = 3600      # 1 hour
    
    @validator("REDIS_URL", pre=True)
    def assemble_redis_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        if isinstance(v, str):
            return v
        
        scheme = "rediss" if values.get("REDIS_SSL") else "redis"
        password = values.get("REDIS_PASSWORD")
        auth = f":{password}@" if password else ""
        
        return f"{scheme}://{auth}{values.get('REDIS_HOST')}:{values.get('REDIS_PORT')}/{values.get('REDIS_DB')}"
    
    class Config:
        env_prefix = ""
        case_sensitive = True


class SecuritySettings(BaseSettings):
    """Security and authentication settings."""
    
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    JWT_SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Password hashing
    BCRYPT_ROUNDS: int = 12
    
    # CORS Settings
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:8000"
    CORS_ALLOW_CREDENTIALS: bool = True
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_BURST: int = 10
    
    # Security Headers
    SECURITY_HEADERS_ENABLED: bool = True
    HSTS_MAX_AGE: int = 31536000
    FORCE_HTTPS: bool = False
    
    # SSL/TLS
    SSL_CERT_PATH: Optional[str] = None
    SSL_KEY_PATH: Optional[str] = None
    
    @validator("SECRET_KEY", "JWT_SECRET_KEY")
    def validate_secret_keys(cls, v):
        if len(v) < 32:
            raise ValueError("Secret keys must be at least 32 characters long")
        return v
    
    class Config:
        env_prefix = ""
        case_sensitive = True


class AISettings(BaseSettings):
    """AI models and providers configuration."""
    
    # OpenAI
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_ORG_ID: Optional[str] = None
    OPENAI_DEFAULT_MODEL: str = "gpt-4-turbo-preview"
    OPENAI_EMBEDDING_MODEL: str = "text-embedding-3-small"
    OPENAI_MAX_TOKENS: int = 4000
    OPENAI_TEMPERATURE: float = 0.7
    
    # Anthropic
    ANTHROPIC_API_KEY: Optional[str] = None
    ANTHROPIC_DEFAULT_MODEL: str = "claude-3-sonnet-20240229"
    ANTHROPIC_MAX_TOKENS: int = 4000
    
    # Other AI Providers
    MANUS_API_KEY: Optional[str] = None
    GENSPARK_API_KEY: Optional[str] = None
    CONTEXT_IA_API_KEY: Optional[str] = None
    SKYWORK_API_KEY: Optional[str] = None
    
    # AI Cost Management
    AI_BUDGET_DAILY_USD: float = 100.00
    AI_BUDGET_MONTHLY_USD: float = 3000.00
    AI_FALLBACK_MODEL: str = "gpt-3.5-turbo"
    
    @validator("OPENAI_TEMPERATURE")
    def validate_temperature(cls, v):
        if not 0.0 <= v <= 2.0:
            raise ValueError("Temperature must be between 0.0 and 2.0")
        return v
    
    @validator("AI_BUDGET_DAILY_USD", "AI_BUDGET_MONTHLY_USD")
    def validate_budgets(cls, v):
        if v < 0:
            raise ValueError("Budget values must be positive")
        return v
    
    class Config:
        env_prefix = ""
        case_sensitive = True


class RAGSettings(BaseSettings):
    """RAG and vector database configuration."""
    
    # Chroma DB
    CHROMA_HOST: str = "localhost"
    CHROMA_PORT: int = 8001
    CHROMA_COLLECTION_NAME: str = "cro_knowledge"
    CHROMA_PERSIST_DIRECTORY: str = "./data/chroma"
    
    # Embedding Configuration
    EMBEDDING_DIMENSION: int = 1536
    EMBEDDING_BATCH_SIZE: int = 100
    RAG_TOP_K: int = 5
    RAG_SIMILARITY_THRESHOLD: float = 0.7
    
    @validator("RAG_SIMILARITY_THRESHOLD")
    def validate_similarity_threshold(cls, v):
        if not 0.0 <= v <= 1.0:
            raise ValueError("Similarity threshold must be between 0.0 and 1.0")
        return v
    
    class Config:
        env_prefix = ""
        case_sensitive = True


class WhatsAppSettings(BaseSettings):
    """WhatsApp Business API configuration."""
    
    WHATSAPP_PROVIDER: str = "360dialog"  # 360dialog, meta, infobip
    WHATSAPP_API_KEY: Optional[str] = None
    WHATSAPP_API_URL: str = "https://waba.360dialog.io"
    WHATSAPP_PHONE_NUMBER_ID: Optional[str] = None
    WHATSAPP_BUSINESS_ACCOUNT_ID: Optional[str] = None
    WHATSAPP_WEBHOOK_VERIFY_TOKEN: Optional[str] = None
    WHATSAPP_WEBHOOK_SECRET: Optional[str] = None
    
    # Twilio (alternative)
    TWILIO_ACCOUNT_SID: Optional[str] = None
    TWILIO_AUTH_TOKEN: Optional[str] = None
    TWILIO_WHATSAPP_NUMBER: Optional[str] = None
    
    # Limits
    WHATSAPP_DAILY_MESSAGE_LIMIT: int = 1000
    WHATSAPP_RATE_LIMIT_PER_SECOND: int = 10
    
    @validator("WHATSAPP_PROVIDER")
    def validate_provider(cls, v):
        allowed_providers = ["360dialog", "meta", "infobip", "twilio"]
        if v not in allowed_providers:
            raise ValueError(f"Provider must be one of: {allowed_providers}")
        return v
    
    class Config:
        env_prefix = ""
        case_sensitive = True


class GoogleSettings(BaseSettings):
    """Google APIs configuration."""
    
    GOOGLE_CLOUD_PROJECT_ID: Optional[str] = None
    GOOGLE_APPLICATION_CREDENTIALS: Optional[str] = None
    
    # Google Drive API
    GOOGLE_DRIVE_FOLDER_ID: Optional[str] = None
    
    # Google Calendar API
    GOOGLE_CALENDAR_ID: str = "primary"
    
    # Google Sheets API
    GOOGLE_SHEETS_SPREADSHEET_ID: Optional[str] = None
    
    # Gmail API
    GMAIL_USER_EMAIL: Optional[EmailStr] = None
    
    # Google Cloud Storage
    GCS_BUCKET_NAME: Optional[str] = None
    GCS_BUCKET_REGION: str = "us-central1"
    
    class Config:
        env_prefix = ""
        case_sensitive = True


class NotionSettings(BaseSettings):
    """Notion API configuration."""
    
    NOTION_API_KEY: Optional[str] = None
    NOTION_DATABASE_ID: Optional[str] = None
    NOTION_PAGE_ID: Optional[str] = None
    
    class Config:
        env_prefix = ""
        case_sensitive = True


class CRMSettings(BaseSettings):
    """CRM integration configuration."""
    
    # HubSpot
    HUBSPOT_API_KEY: Optional[str] = None
    HUBSPOT_PORTAL_ID: Optional[str] = None
    
    # Salesforce
    SALESFORCE_CLIENT_ID: Optional[str] = None
    SALESFORCE_CLIENT_SECRET: Optional[str] = None
    SALESFORCE_USERNAME: Optional[str] = None
    SALESFORCE_PASSWORD: Optional[str] = None
    SALESFORCE_SECURITY_TOKEN: Optional[str] = None
    
    class Config:
        env_prefix = ""
        case_sensitive = True


class EmailSettings(BaseSettings):
    """Email configuration."""
    
    # SMTP Settings
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: Optional[EmailStr] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_TLS: bool = True
    SMTP_SSL: bool = False
    
    # Email Templates
    EMAIL_FROM_NAME: str = "CRO AI Agent"
    EMAIL_FROM_ADDRESS: Optional[EmailStr] = None
    EMAIL_REPLY_TO: Optional[EmailStr] = None
    
    # Limits
    EMAIL_DAILY_SEND_LIMIT: int = 5000
    EMAIL_RATE_LIMIT_PER_MINUTE: int = 100
    
    class Config:
        env_prefix = ""
        case_sensitive = True


class CelerySettings(BaseSettings):
    """Celery background tasks configuration."""
    
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"
    CELERY_TASK_SERIALIZER: str = "json"
    CELERY_RESULT_SERIALIZER: str = "json"
    CELERY_ACCEPT_CONTENT: List[str] = ["json"]
    CELERY_TIMEZONE: str = "America/Sao_Paulo"
    CELERY_ENABLE_UTC: bool = True
    
    # Task Timeouts
    CELERY_TASK_SOFT_TIME_LIMIT: int = 300
    CELERY_TASK_TIME_LIMIT: int = 600
    
    class Config:
        env_prefix = ""
        case_sensitive = True


class ObservabilitySettings(BaseSettings):
    """Observability and monitoring configuration."""
    
    # Prometheus
    PROMETHEUS_PORT: int = 9090
    METRICS_ENABLED: bool = True
    
    # OpenTelemetry
    OTEL_SERVICE_NAME: str = "cro-ai-agent"
    OTEL_SERVICE_VERSION: str = "1.0.0"
    OTEL_EXPORTER_OTLP_ENDPOINT: str = "http://localhost:4317"
    OTEL_RESOURCE_ATTRIBUTES: str = "service.name=cro-ai-agent,service.version=1.0.0"
    
    # Logging
    LOG_FORMAT: str = "json"  # json, text
    LOG_FILE_PATH: str = "./logs/app.log"
    LOG_ROTATION: str = "1 day"
    LOG_RETENTION: str = "30 days"
    
    # Health Checks
    HEALTH_CHECK_INTERVAL: int = 30
    HEALTH_CHECK_TIMEOUT: int = 10
    
    class Config:
        env_prefix = ""
        case_sensitive = True


class BusinessSettings(BaseSettings):
    """Business-specific configuration for +Pet / Mais Pet."""
    
    COMPANY_NAME: str = "+Pet / Mais Pet"
    COMPANY_DOMAIN: str = "maispetoficial.com.br"
    COMPANY_TIMEZONE: str = "America/Sao_Paulo"
    COMPANY_CURRENCY: str = "BRL"
    COMPANY_LANGUAGE: str = "pt-BR"
    
    # Business Hours
    BUSINESS_HOURS_START: str = "09:00"
    BUSINESS_HOURS_END: str = "18:00"
    BUSINESS_DAYS: str = "monday,tuesday,wednesday,thursday,friday"
    
    # Campaign Settings
    DEFAULT_CPA_TARGET: float = 50.00
    DEFAULT_BUDGET_DAILY: float = 500.00
    DEFAULT_CAMPAIGN_DURATION_DAYS: int = 30
    
    # Revenue Targets
    MONTHLY_REVENUE_TARGET: float = 100000.00
    QUARTERLY_REVENUE_TARGET: float = 300000.00
    ANNUAL_REVENUE_TARGET: float = 1200000.00
    
    # KPI Thresholds
    CAC_WARNING_THRESHOLD: float = 100.00
    CHURN_RATE_WARNING_THRESHOLD: float = 0.05
    LTV_CAC_RATIO_TARGET: float = 3.0
    
    @validator("BUSINESS_HOURS_START", "BUSINESS_HOURS_END")
    def validate_time_format(cls, v):
        import re
        if not re.match(r"^([01]?[0-9]|2[0-3]):[0-5][0-9]$", v):
            raise ValueError("Time must be in HH:MM format")
        return v
    
    class Config:
        env_prefix = ""
        case_sensitive = True


class FileStorageSettings(BaseSettings):
    """File storage and upload configuration."""
    
    UPLOAD_DIR: str = "./uploads"
    TEMP_DIR: str = "./temp"
    MAX_FILE_SIZE_MB: int = 50
    ALLOWED_FILE_TYPES: str = "pdf,docx,xlsx,csv,jpg,jpeg,png,gif"
    
    # File Retention
    FILE_RETENTION_DAYS: int = 90
    TEMP_FILE_CLEANUP_HOURS: int = 24
    
    @property
    def allowed_file_types_list(self) -> List[str]:
        return [ext.strip() for ext in self.ALLOWED_FILE_TYPES.split(",")]
    
    @property
    def max_file_size_bytes(self) -> int:
        return self.MAX_FILE_SIZE_MB * 1024 * 1024
    
    class Config:
        env_prefix = ""
        case_sensitive = True


class LGPDSettings(BaseSettings):
    """LGPD compliance configuration."""
    
    # Data Retention Policies (in months)
    USER_DATA_RETENTION_MONTHS: int = 24
    CONVERSATION_DATA_RETENTION_MONTHS: int = 12
    LOG_DATA_RETENTION_MONTHS: int = 6
    ANALYTICS_DATA_RETENTION_MONTHS: int = 36
    
    # Privacy Settings
    ANONYMIZE_USER_DATA: bool = True
    ENCRYPT_SENSITIVE_DATA: bool = True
    GDPR_COMPLIANCE_MODE: bool = True
    
    # Data Processing Legal Bases
    DEFAULT_LEGAL_BASIS: str = "legitimate_interest"
    
    @validator("DEFAULT_LEGAL_BASIS")
    def validate_legal_basis(cls, v):
        allowed_bases = [
            "consent", "contract", "legal_obligation", 
            "vital_interests", "public_task", "legitimate_interest"
        ]
        if v not in allowed_bases:
            raise ValueError(f"Legal basis must be one of: {allowed_bases}")
        return v
    
    class Config:
        env_prefix = ""
        case_sensitive = True


class AgentSettings(BaseSettings):
    """AI Agent configuration."""
    
    # Agent Behavior
    AGENT_MAX_ITERATIONS: int = 10
    AGENT_TIMEOUT_SECONDS: int = 300
    AGENT_MEMORY_WINDOW_SIZE: int = 50
    
    # Agent Costs (USD per task)
    AGENT_COST_BUDGET_PER_TASK: float = 5.00
    AGENT_COST_WARNING_THRESHOLD: float = 3.00
    
    # Agent Capabilities
    AGENT_CAN_EXECUTE_ACTIONS: bool = True
    AGENT_CAN_SEND_MESSAGES: bool = True
    AGENT_CAN_CREATE_CALENDAR_EVENTS: bool = True
    AGENT_CAN_MODIFY_SPREADSHEETS: bool = True
    AGENT_REQUIRES_HUMAN_APPROVAL: bool = False
    
    class Config:
        env_prefix = ""
        case_sensitive = True


class WebhookSettings(BaseSettings):
    """Webhook configuration."""
    
    WEBHOOK_BASE_URL: Optional[AnyHttpUrl] = None
    WEBHOOK_SECRET: Optional[str] = None
    
    # Specific Webhook URLs
    WHATSAPP_WEBHOOK_URL: Optional[AnyHttpUrl] = None
    GOOGLE_WEBHOOK_URL: Optional[AnyHttpUrl] = None
    NOTION_WEBHOOK_URL: Optional[AnyHttpUrl] = None
    HUBSPOT_WEBHOOK_URL: Optional[AnyHttpUrl] = None
    
    class Config:
        env_prefix = ""
        case_sensitive = True


class FeatureFlagSettings(BaseSettings):
    """Feature flags configuration."""
    
    FEATURE_RAG_ENABLED: bool = True
    FEATURE_WHATSAPP_ENABLED: bool = True
    FEATURE_EMAIL_CAMPAIGNS_ENABLED: bool = True
    FEATURE_GOOGLE_INTEGRATIONS_ENABLED: bool = True
    FEATURE_NOTION_SYNC_ENABLED: bool = True
    FEATURE_CRM_SYNC_ENABLED: bool = True
    FEATURE_AI_COST_OPTIMIZATION_ENABLED: bool = True
    FEATURE_ADVANCED_ANALYTICS_ENABLED: bool = True
    
    class Config:
        env_prefix = ""
        case_sensitive = True


class DevelopmentSettings(BaseSettings):
    """Development and testing configuration."""
    
    # Mock Services
    MOCK_WHATSAPP_API: bool = False
    MOCK_GOOGLE_APIS: bool = False
    MOCK_AI_PROVIDERS: bool = False
    
    # Debug Settings
    SQLALCHEMY_ECHO: bool = False
    SHOW_SQL_QUERIES: bool = False
    PROFILE_REQUESTS: bool = False
    
    class Config:
        env_prefix = ""
        case_sensitive = True


class Settings(BaseSettings):
    """Main application settings combining all configuration sections."""
    
    # Application Settings
    APP_NAME: str = "CRO AI Agent"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"
    
    # Server Configuration
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 1
    RELOAD: bool = True
    
    # Performance
    GZIP_COMPRESSION: bool = True
    STATIC_FILE_CACHE_MAX_AGE: int = 86400
    
    # Backup Configuration
    BACKUP_ENABLED: bool = True
    BACKUP_SCHEDULE: str = "0 2 * * *"  # Daily at 2 AM
    BACKUP_RETENTION_DAYS: int = 30
    BACKUP_S3_BUCKET: Optional[str] = None
    
    # Timezone & Localization
    DEFAULT_TIMEZONE: str = "America/Sao_Paulo"
    DEFAULT_LOCALE: str = "pt_BR"
    DEFAULT_CURRENCY: str = "BRL"
    DATE_FORMAT: str = "%d/%m/%Y"
    TIME_FORMAT: str = "%H:%M"
    DATETIME_FORMAT: str = "%d/%m/%Y %H:%M"
    
    # Automation Triggers
    AUTO_CAMPAIGN_OPTIMIZATION: bool = True
    AUTO_BUDGET_ADJUSTMENT: bool = True
    AUTO_AUDIENCE_EXPANSION: bool = True
    AUTO_CREATIVE_TESTING: bool = True
    
    # Nested settings
    database: DatabaseSettings = DatabaseSettings()
    redis: RedisSettings = RedisSettings()
    security: SecuritySettings = SecuritySettings()
    ai: AISettings = AISettings()
    rag: RAGSettings = RAGSettings()
    whatsapp: WhatsAppSettings = WhatsAppSettings()
    google: GoogleSettings = GoogleSettings()
    notion: NotionSettings = NotionSettings()
    crm: CRMSettings = CRMSettings()
    email: EmailSettings = EmailSettings()
    celery: CelerySettings = CelerySettings()
    observability: ObservabilitySettings = ObservabilitySettings()
    business: BusinessSettings = BusinessSettings()
    file_storage: FileStorageSettings = FileStorageSettings()
    lgpd: LGPDSettings = LGPDSettings()
    agent: AgentSettings = AgentSettings()
    webhooks: WebhookSettings = WebhookSettings()
    features: FeatureFlagSettings = FeatureFlagSettings()
    development: DevelopmentSettings = DevelopmentSettings()
    
    @validator("ENVIRONMENT")
    def validate_environment(cls, v):
        allowed_envs = ["development", "staging", "production"]
        if v not in allowed_envs:
            raise ValueError(f"Environment must be one of: {allowed_envs}")
        return v
    
    @validator("LOG_LEVEL")
    def validate_log_level(cls, v):
        allowed_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed_levels:
            raise ValueError(f"Log level must be one of: {allowed_levels}")
        return v.upper()
    
    @root_validator
    def validate_production_settings(cls, values):
        """Validate production-specific settings."""
        environment = values.get("ENVIRONMENT")
        
        if environment == "production":
            # Ensure security settings are properly configured
            if values.get("DEBUG", True):
                raise ValueError("DEBUG must be False in production")
            
            if not values.get("security", {}).get("FORCE_HTTPS", False):
                import warnings
                warnings.warn("FORCE_HTTPS should be True in production")
            
            # Ensure secrets are not default values
            secret_key = values.get("security", {}).get("SECRET_KEY", "")
            if len(secret_key) < 32:
                raise ValueError("SECRET_KEY must be properly configured in production")
        
        return values
    
    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT == "development"
    
    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"
    
    @property
    def is_staging(self) -> bool:
        return self.ENVIRONMENT == "staging"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        
        # Allow nested models to be updated from environment variables
        env_nested_delimiter = "__"
        
        # Example: DATABASE__HOST=localhost will set database.DATABASE_HOST
        
        @classmethod
        def customise_sources(
            cls,
            init_settings,
            env_settings,
            file_secret_settings,
        ):
            return (
                init_settings,
                env_settings,
                file_secret_settings,
            )


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    Uses lru_cache to ensure settings are loaded only once
    and cached for subsequent calls.
    """
    return Settings()


# Convenience functions for accessing nested settings
def get_database_settings() -> DatabaseSettings:
    """Get database settings."""
    return get_settings().database


def get_redis_settings() -> RedisSettings:
    """Get Redis settings."""
    return get_settings().redis


def get_security_settings() -> SecuritySettings:
    """Get security settings."""
    return get_settings().security


def get_ai_settings() -> AISettings:
    """Get AI settings."""
    return get_settings().ai


def get_rag_settings() -> RAGSettings:
    """Get RAG settings."""
    return get_settings().rag


def get_whatsapp_settings() -> WhatsAppSettings:
    """Get WhatsApp settings."""
    return get_settings().whatsapp


def get_google_settings() -> GoogleSettings:
    """Get Google settings."""
    return get_settings().google


def get_notion_settings() -> NotionSettings:
    """Get Notion settings."""
    return get_settings().notion


def get_crm_settings() -> CRMSettings:
    """Get CRM settings."""
    return get_settings().crm


def get_email_settings() -> EmailSettings:
    """Get email settings."""
    return get_settings().email


def get_celery_settings() -> CelerySettings:
    """Get Celery settings."""
    return get_settings().celery


def get_observability_settings() -> ObservabilitySettings:
    """Get observability settings."""
    return get_settings().observability


def get_business_settings() -> BusinessSettings:
    """Get business settings."""
    return get_settings().business


def get_file_storage_settings() -> FileStorageSettings:
    """Get file storage settings."""
    return get_settings().file_storage


def get_lgpd_settings() -> LGPDSettings:
    """Get LGPD settings."""
    return get_settings().lgpd


def get_agent_settings() -> AgentSettings:
    """Get agent settings."""
    return get_settings().agent


def get_webhook_settings() -> WebhookSettings:
    """Get webhook settings."""
    return get_settings().webhooks


def get_feature_flags() -> FeatureFlagSettings:
    """Get feature flags."""
    return get_settings().features


def get_development_settings() -> DevelopmentSettings:
    """Get development settings."""
    return get_settings().development


# Export main settings instance
settings = get_settings()
