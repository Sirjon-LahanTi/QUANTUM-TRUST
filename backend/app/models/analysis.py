"""
QuantumTrust Backend — SQLAlchemy ORM models
"""
import json
from datetime import datetime, timezone

from sqlalchemy import String, Integer, Float, Boolean, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)

    # Document info
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    pdf_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    # Signature summary
    signature_present: Mapped[bool] = mapped_column(Boolean, default=False)
    signature_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    signature_count: Mapped[int] = mapped_column(Integer, default=0)

    # Security summary
    threat_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    threat_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    verdict: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # Full JSON result
    full_result: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def get_full_result(self) -> dict:
        try:
            return json.loads(self.full_result)
        except (json.JSONDecodeError, TypeError):
            return {}

    def set_full_result(self, data: dict) -> None:
        self.full_result = json.dumps(data, default=str)


class Fingerprint(Base):
    """Stores document fingerprints for fast duplicate detection."""
    __tablename__ = "fingerprints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    analysis_id: Mapped[str] = mapped_column(String(64), nullable=False)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
