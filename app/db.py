"""SQLAlchemy models and session/engine setup."""
from __future__ import annotations

import datetime as dt
import os

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    event,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker

DB_PATH = os.environ.get("PATHSCOPE_DB_PATH", "data/monitor.db")


class Base(DeclarativeBase):
    pass


class Run(Base):
    __tablename__ = "runs"

    id = Column(Integer, primary_key=True)
    target = Column(String, index=True, nullable=False)
    timestamp = Column(DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    resolved_ip = Column(String, nullable=True)
    dns_ms = Column(Float, nullable=True)
    reverse_dns_name = Column(String, nullable=True)
    reverse_dns_match = Column(Boolean, nullable=True)
    reverse_dns_error = Column(Text, nullable=True)
    public_dns_ips = Column(Text, nullable=True)
    public_dns_status = Column(String, nullable=True)
    dns_validation_warning = Column(Text, nullable=True)
    dns_sinkhole_match = Column(Boolean, nullable=True)
    dns_sinkhole_range = Column(String, nullable=True)
    success = Column(Boolean, default=False)
    error = Column(String, nullable=True)
    path_signature = Column(Text, nullable=True)
    path_changed = Column(Boolean, default=False)
    endpoint_probe_protocol = Column(String, nullable=True)
    endpoint_avg_ms = Column(Float, nullable=True)
    endpoint_loss_pct = Column(Float, nullable=True)
    endpoint_jitter_ms = Column(Float, nullable=True)
    endpoint_error = Column(Text, nullable=True)

    hops = relationship("Hop", back_populates="run", cascade="all, delete-orphan")
    port_checks = relationship("PortCheck", back_populates="run", cascade="all, delete-orphan")


class Hop(Base):
    __tablename__ = "hops"

    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    hop_num = Column(Integer)
    host = Column(String)
    loss_pct = Column(Float, nullable=True)
    sent = Column(Integer, nullable=True)
    last_ms = Column(Float, nullable=True)
    avg_ms = Column(Float, nullable=True)
    best_ms = Column(Float, nullable=True)
    worst_ms = Column(Float, nullable=True)
    stdev_ms = Column(Float, nullable=True)
    asn = Column(String, nullable=True)
    org = Column(String, nullable=True)
    country = Column(String, nullable=True)
    city = Column(String, nullable=True)

    run = relationship("Run", back_populates="hops")


class PortCheck(Base):
    __tablename__ = "port_checks"

    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    protocol = Column(String)
    port = Column(Integer)
    success = Column(Boolean)
    latency_ms = Column(Float, nullable=True)
    error = Column(String, nullable=True)

    run = relationship("Run", back_populates="port_checks")


class AlertEvent(Base):
    __tablename__ = "alert_events"

    id = Column(Integer, primary_key=True)
    target = Column(String, index=True, nullable=False)
    timestamp = Column(DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    severity = Column(String, nullable=False)
    kind = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    details = Column(Text, nullable=True)
    run_id = Column(Integer, ForeignKey("runs.id", ondelete="SET NULL"), nullable=True)


os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False, "timeout": 30})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


@event.listens_for(engine, "connect")
def _configure_sqlite(dbapi_connection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA busy_timeout=30000")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


def init_db() -> None:
    Base.metadata.create_all(engine)
    _migrate_sqlite()


def _migrate_sqlite() -> None:
    with engine.connect() as conn:
        columns = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(runs)").fetchall()}
        if "path_signature" not in columns:
            conn.exec_driver_sql("ALTER TABLE runs ADD COLUMN path_signature TEXT")
        if "path_changed" not in columns:
            conn.exec_driver_sql("ALTER TABLE runs ADD COLUMN path_changed BOOLEAN DEFAULT 0")
        if "endpoint_probe_protocol" not in columns:
            conn.exec_driver_sql("ALTER TABLE runs ADD COLUMN endpoint_probe_protocol TEXT")
        if "endpoint_avg_ms" not in columns:
            conn.exec_driver_sql("ALTER TABLE runs ADD COLUMN endpoint_avg_ms FLOAT")
        if "endpoint_loss_pct" not in columns:
            conn.exec_driver_sql("ALTER TABLE runs ADD COLUMN endpoint_loss_pct FLOAT")
        if "endpoint_jitter_ms" not in columns:
            conn.exec_driver_sql("ALTER TABLE runs ADD COLUMN endpoint_jitter_ms FLOAT")
        if "endpoint_error" not in columns:
            conn.exec_driver_sql("ALTER TABLE runs ADD COLUMN endpoint_error TEXT")
        if "reverse_dns_name" not in columns:
            conn.exec_driver_sql("ALTER TABLE runs ADD COLUMN reverse_dns_name TEXT")
        if "reverse_dns_match" not in columns:
            conn.exec_driver_sql("ALTER TABLE runs ADD COLUMN reverse_dns_match BOOLEAN")
        if "reverse_dns_error" not in columns:
            conn.exec_driver_sql("ALTER TABLE runs ADD COLUMN reverse_dns_error TEXT")
        if "public_dns_ips" not in columns:
            conn.exec_driver_sql("ALTER TABLE runs ADD COLUMN public_dns_ips TEXT")
        if "public_dns_status" not in columns:
            conn.exec_driver_sql("ALTER TABLE runs ADD COLUMN public_dns_status TEXT")
        if "dns_validation_warning" not in columns:
            conn.exec_driver_sql("ALTER TABLE runs ADD COLUMN dns_validation_warning TEXT")
        if "dns_sinkhole_match" not in columns:
            conn.exec_driver_sql("ALTER TABLE runs ADD COLUMN dns_sinkhole_match BOOLEAN")
        if "dns_sinkhole_range" not in columns:
            conn.exec_driver_sql("ALTER TABLE runs ADD COLUMN dns_sinkhole_range TEXT")
        alert_columns = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(alert_events)").fetchall()}
        if "details" not in alert_columns:
            conn.exec_driver_sql("ALTER TABLE alert_events ADD COLUMN details TEXT")
        conn.commit()
