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
    login_attempts = Column(Integer, default=0)
    login_success = Column(Boolean, default=False)
    commands_run = Column(Integer, default=0)
    files_downloaded = Column(Integer, default=0)
    severity = Column(String, default="low")
    attack_type = Column(String, nullable=True, default="SSH Connect")
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    events = relationship("Event", back_populates="session", lazy="select")


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
