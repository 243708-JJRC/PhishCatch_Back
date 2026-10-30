from typing import Any, Dict, List
from sqlalchemy.orm import Session

from app.models.scan_history import RiskLevel, ScanHistory, ScanType


def create_scan_history(
    db: Session,
    user_id: int,
    target: str,
    scan_type: str,
    risk_level: str,
    raw_result: Dict[str, Any],
) -> ScanHistory:
    resolved_scan_type = ScanType(scan_type) if scan_type in ScanType._value2member_map_ else ScanType.URL
    resolved_risk_level = RiskLevel(risk_level) if risk_level in RiskLevel._value2member_map_ else RiskLevel.PENDING

    db_scan = ScanHistory(
        user_id=user_id,
        target=target,
        scan_type=resolved_scan_type,
        risk_level=resolved_risk_level,
        raw_result=raw_result,
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    return db_scan


def get_user_scans(
    db: Session,
    user_id: int,
    skip: int = 0,
    limit: int = 20,
) -> List[ScanHistory]:

    return (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == user_id)
        .order_by(ScanHistory.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

def get_user_scans(
    db: Session,
    user_id: int,
    skip: int = 0,
    limit: int = 20,
) -> List[ScanHistory]:
    return (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == user_id)
        .order_by(ScanHistory.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
