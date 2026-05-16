from datetime import datetime
from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey,
    Integer, String, Text, UniqueConstraint, func,
)
from sqlalchemy.orm import relationship

from .database import Base


class IPEnrichment(Base):
    __tablename__ = "ip_enrichments"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String, unique=True, nullable=False, index=True)

    # GeoIP (ip-api.com)
    country = Column(String, nullable=True)
    country_code = Column(String(2), nullable=True)
    city = Column(String, nullable=True)
    region = Column(String, nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    isp = Column(String, nullable=True)

    # VirusTotal
    vt_malicious = Column(Integer, nullable=True)
    vt_suspicious = Column(Integer, nullable=True)
    vt_harmless = Column(Integer, nullable=True)
    vt_total = Column(Integer, nullable=True)
    vt_reputation = Column(Integer, nullable=True)

    enrichment_status = Column(String, default="pending")  # pending/geoip_done/complete/failed
    enriched_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String, unique=True, nullable=False, index=True)
    src_ip = Column(String, nullable=False, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True, default=22)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=True)
    duration_secs = Column(Float, nullable=True)
    sensor = Column(String, nullable=True)
    protocol = Column(String(20), default="ssh")          # ssh|http|smb|ftp|mysql|mssql|sip|telnet
    login_attempts = Column(Integer, default=0)
    login_success = Column(Boolean, default=False)
    commands_run = Column(Integer, default=0)
    files_downloaded = Column(Integer, default=0)
    severity = Column(String, default="low")
    attack_type = Column(String, nullable=True, default="SSH Connect")
    is_anomaly = Column(Boolean, default=False)
    anomaly_score = Column(Float, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    events = relationship("Event", back_populates="session", lazy="select")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="analyst")  # admin | analyst | viewer
    full_name = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class RetentionConfig(Base):
    __tablename__ = "retention_config"

    id = Column(Integer, primary_key=True, default=1)
    events_days = Column(Integer, default=60)
    sessions_days = Column(Integer, default=90)
    enrichment_days = Column(Integer, default=90)
    last_purge_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    condition = Column(String(50), nullable=False)
    threshold = Column(Integer, nullable=False, default=1)
    severity = Column(String(20), nullable=False, default="high")
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class AlertInvestigation(Base):
    __tablename__ = "alert_investigations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(Integer, ForeignKey("events.id"), unique=True, nullable=False, index=True)
    status = Column(String(30), nullable=False, default="open")  # open|reviewed|false_positive|escalated
    note = Column(Text, nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    false_positive_at = Column(DateTime, nullable=True)
    escalated_at = Column(DateTime, nullable=True)
    updated_by = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    event = relationship("Event")


class NotificationConfig(Base):
    __tablename__ = "notification_config"

    id = Column(Integer, primary_key=True, default=1)
    webhook_url = Column(String(500), nullable=True)
    webhook_enabled = Column(Boolean, default=False)
    email_to = Column(String(255), nullable=True)
    email_host = Column(String(255), nullable=True)
    email_port = Column(Integer, default=587)
    email_user = Column(String(255), nullable=True)
    email_pass = Column(String(255), nullable=True)
    email_enabled = Column(Boolean, default=False)
    min_severity = Column(String(20), default="high")
    tg_bot_token = Column(String(500), nullable=True)
    tg_chat_id   = Column(String(100), nullable=True)
    tg_enabled   = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class HoneypotConfig(Base):
    __tablename__ = "honeypot_config"

    id = Column(Integer, primary_key=True, default=1)
    honeypot_type = Column(String(50), default="cowrie")
    connection_mode = Column(String(20), default="live")
    host = Column(String(255), default="cowrie")
    port = Column(Integer, default=2222)
    protocol = Column(String(10), default="TCP")
    sensor_name = Column(String(100), default="honeypot-01")
    log_path = Column(String(500), default="/var/log/cowrie/cowrie.json")
    notes = Column(Text, nullable=True)
    last_test_status = Column(String(20), nullable=True)
    last_test_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String, nullable=False)
    session_id = Column(String, ForeignKey("sessions.session_id"), nullable=False, index=True)
    src_ip = Column(String, nullable=False, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    sensor = Column(String, nullable=True)
    protocol = Column(String(20), default="ssh")          # ssh|http|smb|ftp|mysql|mssql|sip|telnet
    username = Column(String, nullable=True)
    password = Column(String, nullable=True)
    command_input = Column(String, nullable=True)
    download_url = Column(String, nullable=True)
    download_path = Column(String, nullable=True)
    duration = Column(Float, nullable=True)
    raw_json = Column(Text, nullable=False)
    severity = Column(String, default="low")
    attack_type = Column(String, nullable=True)
    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        UniqueConstraint("session_id", "event_id", "timestamp", name="uq_event_dedup"),
    )

    session = relationship("Session", back_populates="events")


class MalwareSample(Base):
    """Malware binaries captured by Dionaea."""
    __tablename__ = "malware_samples"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sha256 = Column(String(64), unique=True, nullable=False, index=True)
    md5 = Column(String(32), nullable=True)
    sha512 = Column(String(128), nullable=True)
    file_size = Column(Integer, nullable=True)
    file_type = Column(String(50), nullable=True)   # PE32, ELF, script, etc.
    first_seen = Column(DateTime, nullable=False, default=func.now())
    last_seen = Column(DateTime, nullable=False, default=func.now())
    download_count = Column(Integer, default=1)
    src_ip = Column(String, nullable=True, index=True)
    download_url = Column(String(500), nullable=True)
    protocol = Column(String(20), nullable=True)    # http | ftp | smb
    sensor = Column(String(100), nullable=True)
    # VirusTotal scan results (enriched async)
    vt_detections = Column(Integer, nullable=True)
    vt_total = Column(Integer, nullable=True)
    vt_family = Column(String(100), nullable=True)
    vt_checked_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())
