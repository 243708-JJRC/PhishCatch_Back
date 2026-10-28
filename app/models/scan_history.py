import enum
from datetime import datetime
from typing import Any, Dict
from sqlalchemy import (
    Column,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Integer,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class ScanType(str, enum.Enum):
    URL = "url"
    FILE = "file"


class RiskLevel(str, enum.Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    PENDING = "pending"


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    target = Column(String(2048), nullable=False)
    scan_type = Column(
        SAEnum(ScanType, name="scan_type_enum", native_enum=False),
        nullable=False,
        default=ScanType.URL,
    )
    risk_level = Column(
        SAEnum(RiskLevel, name="risk_level_enum", native_enum=False),
        nullable=False,
        default=RiskLevel.PENDING,
    )
    raw_result = Column(JSONB().with_variant(JSON, "sqlite"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    user = relationship("User", back_populates="scans")

    def __repr__(self) -> str:
        return f"<ScanHistory id={self.id} user_id={self.user_id} target={self.target[:30]} risk={self.risk_level}>"
