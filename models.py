
"""
CRO AI Agent - Database Models
==============================

SQLAlchemy models for all core entities in the CRO AI Agent system.
Includes users, campaigns, contacts, segments, messages, tasks, and more.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import relationship, validates
from sqlalchemy.sql import func

from app.core.database import Base


# Enums
class UserStatus(PyEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"


class ContactStatus(PyEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNSUBSCRIBED = "unsubscribed"
    BOUNCED = "bounced"
    BLOCKED = "blocked"


class CampaignStatus(PyEnum):
    DRAFT = "draft"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class CampaignType(PyEnum):
    WHATSAPP = "whatsapp"
    EMAIL = "email"
    SMS = "sms"
    PUSH = "push"
    SOCIAL = "social"
    ADS = "ads"


class MessageStatus(PyEnum):
    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"
    FAILED = "failed"
    BOUNCED = "bounced"


class TaskStatus(PyEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskPriority(PyEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


class IntegrationStatus(PyEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    PENDING = "pending"


class AgentRunStatus(PyEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# Base model with common fields
class BaseModel(Base):
    """Base model with common fields for all entities."""
    __abstract__ = True
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    updated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary."""
        return {
            column.name: getattr(self, column.name)
            for column in self.__table__.columns
        }


# User and Role models
class Role(BaseModel):
    """User roles and permissions."""
    __tablename__ = "roles"
    
    name = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(Text)
    permissions = Column(JSONB, default=list)  # List of permission strings
    is_system = Column(Boolean, default=False)  # System roles cannot be deleted
    
    # Relationships
    users = relationship("User", secondary="user_roles", back_populates="roles")
    
    def __repr__(self):
        return f"<Role(name='{self.name}')>"


class User(BaseModel):
    """System users."""
    __tablename__ = "users"
    
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=False)
    password_hash = Column(String(255), nullable=False)
    status = Column(Enum(UserStatus), default=UserStatus.ACTIVE, nullable=False)
    
    # Profile information
    avatar_url = Column(String(500))
    phone = Column(String(20))
    timezone = Column(String(50), default="UTC")
    language = Column(String(10), default="pt-BR")
    
    # Security
    last_login_at = Column(DateTime(timezone=True))
    last_login_ip = Column(String(45))
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True))
    email_verified = Column(Boolean, default=False)
    email_verified_at = Column(DateTime(timezone=True))
    
    # Preferences
    preferences = Column(JSONB, default=dict)
    
    # Relationships
    roles = relationship("Role", secondary="user_roles", back_populates="users")
    created_campaigns = relationship("Campaign", foreign_keys="Campaign.created_by")
    created_contacts = relationship("Contact", foreign_keys="Contact.created_by")
    agent_runs = relationship("AgentRun", back_populates="user")
    
    @validates('email')
    def validate_email(self, key, email):
        """Validate email format."""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            raise ValueError("Invalid email format")
        return email.lower()
    
    @hybrid_property
    def is_locked(self):
        """Check if user account is locked."""
        if self.locked_until:
            return datetime.now(timezone.utc) < self.locked_until
        return False
    
    def __repr__(self):
        return f"<User(username='{self.username}', email='{self.email}')>"


class UserRole(Base):
    """Many-to-many relationship between users and roles."""
    __tablename__ = "user_roles"
    
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), primary_key=True)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id"), primary_key=True)
    assigned_at = Column(DateTime(timezone=True), server_default=func.now())
    assigned_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))


# Contact and Segment models
class Contact(BaseModel):
    """Customer contacts and leads."""
    __tablename__ = "contacts"
    
    # Basic information
    email = Column(String(255), index=True)
    phone = Column(String(20), index=True)
    whatsapp = Column(String(20), index=True)
    full_name = Column(String(255))
    first_name = Column(String(100))
    last_name = Column(String(100))
    
    # Status and preferences
    status = Column(Enum(ContactStatus), default=ContactStatus.ACTIVE, nullable=False)
    email_opt_in = Column(Boolean, default=True)
    whatsapp_opt_in = Column(Boolean, default=True)
    sms_opt_in = Column(Boolean, default=True)
    
    # Demographics
    birth_date = Column(DateTime(timezone=True))
    gender = Column(String(20))
    city = Column(String(100))
    state = Column(String(100))
    country = Column(String(100))
    postal_code = Column(String(20))
    
    # Business information
    company = Column(String(255))
    job_title = Column(String(255))
    industry = Column(String(100))
    
    # Engagement metrics
    total_orders = Column(Integer, default=0)
    total_spent = Column(Float, default=0.0)
    last_order_at = Column(DateTime(timezone=True))
    last_interaction_at = Column(DateTime(timezone=True))
    
    # Custom fields and tags
    custom_fields = Column(JSONB, default=dict)
    tags = Column(JSONB, default=list)  # List of tag strings
    
    # Lead scoring
    lead_score = Column(Integer, default=0)
    lifecycle_stage = Column(String(50))  # lead, prospect, customer, etc.
    
    # Source tracking
    source = Column(String(100))  # organic, paid, referral, etc.
    utm_source = Column(String(100))
    utm_medium = Column(String(100))
    utm_campaign = Column(String(100))
    
    # Relationships
    segments = relationship("Segment", secondary="contact_segments", back_populates="contacts")
    messages = relationship("Message", back_populates="contact")
    events = relationship("Event", back_populates="contact")
    
    # Indexes
    __table_args__ = (
        Index('idx_contact_email_status', 'email', 'status'),
        Index('idx_contact_phone_status', 'phone', 'status'),
        Index('idx_contact_tags', 'tags', postgresql_using='gin'),
        Index('idx_contact_custom_fields', 'custom_fields', postgresql_using='gin'),
    )
    
    @validates('email')
    def validate_email(self, key, email):
        """Validate email format."""
        if email:
            import re
            pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(pattern, email):
                raise ValueError("Invalid email format")
            return email.lower()
        return email
    
    def __repr__(self):
        return f"<Contact(email='{self.email}', name='{self.full_name}')>"


class Segment(BaseModel):
    """Contact segments for targeting."""
    __tablename__ = "segments"
    
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    
    # Segment criteria
    criteria = Column(JSONB, nullable=False)  # JSON query for filtering contacts
    is_dynamic = Column(Boolean, default=True)  # Auto-update based on criteria
    
    # Statistics
    contact_count = Column(Integer, default=0)
    last_calculated_at = Column(DateTime(timezone=True))
    
    # Relationships
    contacts = relationship("Contact", secondary="contact_segments", back_populates="segments")
    campaigns = relationship("Campaign", back_populates="segment")
    
    def __repr__(self):
        return f"<Segment(name='{self.name}', count={self.contact_count})>"


class ContactSegment(Base):
    """Many-to-many relationship between contacts and segments."""
    __tablename__ = "contact_segments"
    
    contact_id = Column(UUID(as_uuid=True), ForeignKey("contacts.id"), primary_key=True)
    segment_id = Column(UUID(as_uuid=True), ForeignKey("segments.id"), primary_key=True)
    added_at = Column(DateTime(timezone=True), server_default=func.now())
    added_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))


# Campaign and Message models
class Campaign(BaseModel):
    """Marketing campaigns."""
    __tablename__ = "campaigns"
    
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    type = Column(Enum(CampaignType), nullable=False)
    status = Column(Enum(CampaignStatus), default=CampaignStatus.DRAFT, nullable=False)
    
    # Targeting
    segment_id = Column(UUID(as_uuid=True), ForeignKey("segments.id"))
    
    # Scheduling
    scheduled_at = Column(DateTime(timezone=True))
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    
    # Content and settings
    content = Column(JSONB, nullable=False)  # Campaign content and settings
    settings = Column(JSONB, default=dict)  # Additional campaign settings
    
    # Budget and limits
    budget = Column(Float)
    daily_budget = Column(Float)
    max_contacts = Column(Integer)
    
    # Performance metrics
    total_sent = Column(Integer, default=0)
    total_delivered = Column(Integer, default=0)
    total_opened = Column(Integer, default=0)
    total_clicked = Column(Integer, default=0)
    total_converted = Column(Integer, default=0)
    total_cost = Column(Float, default=0.0)
    
    # A/B testing
    is_ab_test = Column(Boolean, default=False)
    ab_test_config = Column(JSONB)
    
    # Relationships
    segment = relationship("Segment", back_populates="campaigns")
    messages = relationship("Message", back_populates="campaign")
    experiments = relationship("Experiment", back_populates="campaign")
    
    def __repr__(self):
        return f"<Campaign(name='{self.name}', type='{self.type}', status='{self.status}')>"


class Message(BaseModel):
    """Individual messages sent to contacts."""
    __tablename__ = "messages"
    
    # References
    campaign_id = Column(UUID(as_uuid=True), ForeignKey("campaigns.id"), nullable=False)
    contact_id = Column(UUID(as_uuid=True), ForeignKey("contacts.id"), nullable=False)
    
    # Message details
    type = Column(Enum(CampaignType), nullable=False)
    status = Column(Enum(MessageStatus), default=MessageStatus.PENDING, nullable=False)
    
    # Content
    subject = Column(String(500))  # For email
    content = Column(Text, nullable=False)
    content_html = Column(Text)  # HTML version for email
    
    # Delivery tracking
    sent_at = Column(DateTime(timezone=True))
    delivered_at = Column(DateTime(timezone=True))
    opened_at = Column(DateTime(timezone=True))
    clicked_at = Column(DateTime(timezone=True))
    
    # External IDs for tracking
    external_id = Column(String(255), index=True)  # Provider message ID
    tracking_id = Column(String(255), index=True)  # Internal tracking ID
    
    # Error handling
    error_code = Column(String(50))
    error_message = Column(Text)
    retry_count = Column(Integer, default=0)
    
    # Metadata
    metadata = Column(JSONB, default=dict)
    
    # Relationships
    campaign = relationship("Campaign", back_populates="messages")
    contact = relationship("Contact", back_populates="messages")
    
    # Indexes
    __table_args__ = (
        Index('idx_message_campaign_status', 'campaign_id', 'status'),
        Index('idx_message_contact_type', 'contact_id', 'type'),
        Index('idx_message_sent_at', 'sent_at'),
    )
    
    def __repr__(self):
        return f"<Message(type='{self.type}', status='{self.status}', contact_id='{self.contact_id}')>"


# Task and Playbook models
class Task(BaseModel):
    """System tasks and workflows."""
    __tablename__ = "tasks"
    
    title = Column(String(255), nullable=False)
    description = Column(Text)
    type = Column(String(50), nullable=False, index=True)  # email_send, data_sync, etc.
    status = Column(Enum(TaskStatus), default=TaskStatus.PENDING, nullable=False)
    priority = Column(Enum(TaskPriority), default=TaskPriority.MEDIUM, nullable=False)
    
    # Scheduling
    scheduled_at = Column(DateTime(timezone=True))
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    
    # Task configuration
    config = Column(JSONB, nullable=False)  # Task-specific configuration
    result = Column(JSONB)  # Task execution result
    
    # Error handling
    error_message = Column(Text)
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    
    # Dependencies
    depends_on = Column(JSONB, default=list)  # List of task IDs this task depends on
    
    # Relationships
    agent_run_id = Column(UUID(as_uuid=True), ForeignKey("agent_runs.id"))
    agent_run = relationship("AgentRun", back_populates="tasks")
    
    # Indexes
    __table_args__ = (
        Index('idx_task_type_status', 'type', 'status'),
        Index('idx_task_scheduled_at', 'scheduled_at'),
        Index('idx_task_priority_status', 'priority', 'status'),
    )
    
    def __repr__(self):
        return f"<Task(title='{self.title}', type='{self.type}', status='{self.status}')>"


class Playbook(BaseModel):
    """Reusable automation playbooks."""
    __tablename__ = "playbooks"
    
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    category = Column(String(100), index=True)
    
    # Playbook definition
    definition = Column(JSONB, nullable=False)  # Workflow definition
    variables = Column(JSONB, default=dict)  # Template variables
    
    # Usage tracking
    usage_count = Column(Integer, default=0)
    last_used_at = Column(DateTime(timezone=True))
    
    # Versioning
    version = Column(String(20), default="1.0.0")
    is_active = Column(Boolean, default=True)
    
    # Relationships
    agent_runs = relationship("AgentRun", back_populates="playbook")
    
    def __repr__(self):
        return f"<Playbook(name='{self.name}', category='{self.category}')>"


# Experiment model
class Experiment(BaseModel):
    """A/B testing experiments."""
    __tablename__ = "experiments"
    
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    hypothesis = Column(Text)
    
    # Experiment configuration
    campaign_id = Column(UUID(as_uuid=True), ForeignKey("campaigns.id"))
    variants = Column(JSONB, nullable=False)  # List of experiment variants
    traffic_split = Column(JSONB, nullable=False)  # Traffic allocation per variant
    
    # Status and timing
    status = Column(String(50), default="draft", nullable=False)
    started_at = Column(DateTime(timezone=True))
    ended_at = Column(DateTime(timezone=True))
    
    # Success metrics
    primary_metric = Column(String(100), nullable=False)
    secondary_metrics = Column(JSONB, default=list)
    
    # Results
    results = Column(JSONB)
    winner_variant = Column(String(100))
    confidence_level = Column(Float)
    
    # Relationships
    campaign = relationship("Campaign", back_populates="experiments")
    
    def __repr__(self):
        return f"<Experiment(name='{self.name}', status='{self.status}')>"


# Event and Metrics models
class Event(BaseModel):
    """System and user events for analytics."""
    __tablename__ = "events"
    
    # Event identification
    name = Column(String(100), nullable=False, index=True)
    category = Column(String(50), index=True)
    
    # Event data
    properties = Column(JSONB, default=dict)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    contact_id = Column(UUID(as_uuid=True), ForeignKey("contacts.id"))
    session_id = Column(String(255), index=True)
    
    # Context
    ip_address = Column(String(45))
    user_agent = Column(Text)
    referrer = Column(String(500))
    
    # Timestamps
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User")
    contact = relationship("Contact", back_populates="events")
    
    # Indexes
    __table_args__ = (
        Index('idx_event_name_timestamp', 'name', 'timestamp'),
        Index('idx_event_category_timestamp', 'category', 'timestamp'),
        Index('idx_event_contact_timestamp', 'contact_id', 'timestamp'),
        Index('idx_event_properties', 'properties', postgresql_using='gin'),
    )
    
    def __repr__(self):
        return f"<Event(name='{self.name}', category='{self.category}')>"


class MetricsDaily(BaseModel):
    """Daily aggregated metrics."""
    __tablename__ = "metrics_daily"
    
    date = Column(DateTime(timezone=True), nullable=False, index=True)
    metric_name = Column(String(100), nullable=False, index=True)
    metric_category = Column(String(50), index=True)
    
    # Metric values
    value = Column(Float, nullable=False)
    count = Column(Integer, default=1)
    
    # Dimensions for grouping
    dimensions = Column(JSONB, default=dict)
    
    # Unique constraint to prevent duplicates
    __table_args__ = (
        UniqueConstraint('date', 'metric_name', 'dimensions', name='uq_metrics_daily'),
        Index('idx_metrics_date_name', 'date', 'metric_name'),
        Index('idx_metrics_dimensions', 'dimensions', postgresql_using='gin'),
    )
    
    def __repr__(self):
        return f"<MetricsDaily(date='{self.date}', metric='{self.metric_name}', value={self.value})>"


# File and Integration models
class File(BaseModel):
    """Uploaded files and documents."""
    __tablename__ = "files"
    
    filename = Column(String(255), nullable=False)
    original_filename = Column(String(255), nullable=False)
    content_type = Column(String(100), nullable=False)
    size = Column(Integer, nullable=False)
    
    # Storage
    storage_path = Column(String(500), nullable=False)
    storage_provider = Column(String(50), default="local")
    
    # File metadata
    checksum = Column(String(64))  # SHA-256 hash
    metadata = Column(JSONB, default=dict)
    
    # Access control
    is_public = Column(Boolean, default=False)
    access_permissions = Column(JSONB, default=dict)
    
    # Usage tracking
    download_count = Column(Integer, default=0)
    last_accessed_at = Column(DateTime(timezone=True))
    
    def __repr__(self):
        return f"<File(filename='{self.filename}', size={self.size})>"


class Integration(BaseModel):
    """External service integrations."""
    __tablename__ = "integrations"
    
    name = Column(String(100), nullable=False, index=True)
    provider = Column(String(50), nullable=False, index=True)  # whatsapp, google, notion, etc.
    status = Column(Enum(IntegrationStatus), default=IntegrationStatus.PENDING, nullable=False)
    
    # Configuration
    config = Column(JSONB, nullable=False)  # Integration-specific configuration
    credentials = Column(JSONB)  # Encrypted credentials
    
    # Health monitoring
    last_sync_at = Column(DateTime(timezone=True))
    last_error_at = Column(DateTime(timezone=True))
    error_message = Column(Text)
    health_score = Column(Float, default=100.0)  # 0-100 health score
    
    # Usage statistics
    total_requests = Column(Integer, default=0)
    successful_requests = Column(Integer, default=0)
    failed_requests = Column(Integer, default=0)
    
    def __repr__(self):
        return f"<Integration(name='{self.name}', provider='{self.provider}', status='{self.status}')>"


# Audit and Agent Run models
class Audit(BaseModel):
    """Audit trail for system actions."""
    __tablename__ = "audits"
    
    # Action details
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50), nullable=False, index=True)
    resource_id = Column(String(255), index=True)
    
    # User context
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    ip_address = Column(String(45))
    user_agent = Column(Text)
    
    # Change details
    old_values = Column(JSONB)
    new_values = Column(JSONB)
    changes = Column(JSONB)  # Diff of changes
    
    # Context
    context = Column(JSONB, default=dict)
    
    # Timestamp
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User")
    
    # Indexes
    __table_args__ = (
        Index('idx_audit_action_timestamp', 'action', 'timestamp'),
        Index('idx_audit_resource_timestamp', 'resource_type', 'resource_id', 'timestamp'),
        Index('idx_audit_user_timestamp', 'user_id', 'timestamp'),
    )
    
    def __repr__(self):
        return f"<Audit(action='{self.action}', resource='{self.resource_type}')>"


class AgentRun(BaseModel):
    """AI agent execution runs."""
    __tablename__ = "agent_runs"
    
    # Run identification
    name = Column(String(255), nullable=False)
    agent_type = Column(String(50), nullable=False, index=True)  # router, planner, etc.
    status = Column(Enum(AgentRunStatus), default=AgentRunStatus.PENDING, nullable=False)
    
    # User context
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    
    # Execution details
    playbook_id = Column(UUID(as_uuid=True), ForeignKey("playbooks.id"))
    input_data = Column(JSONB, nullable=False)
    output_data = Column(JSONB)
    
    # Timing
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    duration_seconds = Column(Float)
    
    # Resource usage
    tokens_used = Column(Integer, default=0)
    cost = Column(Float, default=0.0)
    
    # Error handling
    error_message = Column(Text)
    error_details = Column(JSONB)
    
    # Metadata
    metadata = Column(JSONB, default=dict)
    trace_id = Column(String(255), index=True)  # For distributed tracing
    
    # Relationships
    user = relationship("User", back_populates="agent_runs")
    playbook = relationship("Playbook", back_populates="agent_runs")
    tasks = relationship("Task", back_populates="agent_run")
    
    # Indexes
    __table_args__ = (
        Index('idx_agent_run_type_status', 'agent_type', 'status'),
        Index('idx_agent_run_user_started', 'user_id', 'started_at'),
        Index('idx_agent_run_trace_id', 'trace_id'),
    )
    
    def __repr__(self):
        return f"<AgentRun(name='{self.name}', agent_type='{self.agent_type}', status='{self.status}')>"


# Event listeners for automatic updates
@event.listens_for(User, 'before_update')
def update_user_timestamp(mapper, connection, target):
    """Update user timestamp on changes."""
    target.updated_at = datetime.now(timezone.utc)


@event.listens_for(Contact, 'before_update')
def update_contact_timestamp(mapper, connection, target):
    """Update contact timestamp and interaction tracking."""
    target.updated_at = datetime.now(timezone.utc)
    target.last_interaction_at = datetime.now(timezone.utc)


@event.listens_for(Campaign, 'before_update')
def update_campaign_status_timestamps(mapper, connection, target):
    """Update campaign status timestamps."""
    target.updated_at = datetime.now(timezone.utc)
    
    # Set started_at when status changes to running
    if target.status == CampaignStatus.RUNNING and not target.started_at:
        target.started_at = datetime.now(timezone.utc)
    
    # Set completed_at when status changes to completed
    if target.status == CampaignStatus.COMPLETED and not target.completed_at:
        target.completed_at = datetime.now(timezone.utc)


@event.listens_for(AgentRun, 'before_update')
def update_agent_run_duration(mapper, connection, target):
    """Calculate duration when agent run completes."""
    target.updated_at = datetime.now(timezone.utc)
    
    if target.status in [AgentRunStatus.COMPLETED, AgentRunStatus.FAILED] and target.started_at:
        if not target.completed_at:
            target.completed_at = datetime.now(timezone.utc)
        
        if target.completed_at and target.started_at:
            duration = target.completed_at - target.started_at
            target.duration_seconds = duration.total_seconds()


# Export all models
__all__ = [
    # Base
    "BaseModel",
    
    # Enums
    "UserStatus",
    "ContactStatus", 
    "CampaignStatus",
    "CampaignType",
    "MessageStatus",
    "TaskStatus",
    "TaskPriority",
    "IntegrationStatus",
    "AgentRunStatus",
    
    # Models
    "User",
    "Role",
    "UserRole",
    "Contact",
    "Segment",
    "ContactSegment",
    "Campaign",
    "Message",
    "Task",
    "Playbook",
    "Experiment",
    "Event",
    "MetricsDaily",
    "File",
    "Integration",
    "Audit",
    "AgentRun",
]
