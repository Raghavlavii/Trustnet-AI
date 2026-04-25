"""SQLAlchemy ORM models for TrustNet AI intelligence database."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Conversation(Base):
    """Top-level record for each submitted message / analysis session."""

    __tablename__ = "conversations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    # ML result
    label: Mapped[str] = mapped_column(String(16))            # "Scam" | "Safe"
    trust_score: Mapped[float] = mapped_column(Float)
    ml_scam_probability: Mapped[float] = mapped_column(Float)
    llm_analysis: Mapped[Optional[str]] = mapped_column(Text)

    # Status
    status: Mapped[str] = mapped_column(String(32), default="analyzed")
    # e.g. analyzed | flagged | reported

    messages: Mapped[list[Message]] = relationship(
        "Message", back_populates="conversation", cascade="all, delete-orphan"
    )
    extracted_intel: Mapped[list[ExtractedIntel]] = relationship(
        "ExtractedIntel", back_populates="conversation", cascade="all, delete-orphan"
    )
    reports: Mapped[list[Report]] = relationship(
        "Report", back_populates="conversation", cascade="all, delete-orphan"
    )


class Message(Base):
    """Individual messages within a conversation."""

    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    conversation_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("conversations.id"), index=True
    )
    role: Mapped[str] = mapped_column(String(16))   # "user" | "system"
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )

    conversation: Mapped[Conversation] = relationship(
        "Conversation", back_populates="messages"
    )


class ExtractedIntel(Base):
    """Structured intelligence extracted from scam messages."""

    __tablename__ = "extracted_intel"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    conversation_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("conversations.id"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )

    # Regex-extracted fields
    phone_numbers: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    email_addresses: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    urls: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    payment_details: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    names_aliases: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    organizations: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    amounts: Mapped[Optional[list]] = mapped_column(JSON, default=list)

    # LLM-structured extraction
    llm_extracted: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)

    # Scam type classification
    scam_type: Mapped[Optional[str]] = mapped_column(String(64))
    scam_indicators: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    risk_level: Mapped[str] = mapped_column(String(16), default="unknown")
    # low | medium | high | critical

    conversation: Mapped[Conversation] = relationship(
        "Conversation", back_populates="extracted_intel"
    )


class Report(Base):
    """Generated authority reports for scam conversations."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    conversation_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("conversations.id"), index=True
    )
    report_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    format: Mapped[str] = mapped_column(String(16), default="json")  # json | pdf
    content: Mapped[dict] = mapped_column(JSON)

    conversation: Mapped[Conversation] = relationship(
        "Conversation", back_populates="reports"
    )
