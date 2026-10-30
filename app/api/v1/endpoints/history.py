from typing import List
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.crud.crud_scan import get_user_scans
from app.db.session import get_db
from app.models.user import User
from app.schemas.scan import ScanHistoryResponse

router = APIRouter()


@router.get(
    "/",
    response_model=List[ScanHistoryResponse],
    status_code=status.HTTP_200_OK,
    summary="Consultar historial de análisis del usuario autenticado",
)
def read_scan_history(
    skip: int = Query(0, ge=0, description="Número de registros a omitir para paginación"),
    limit: int = Query(20, ge=1, le=100, description="Cantidad máxima de registros por página"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[ScanHistoryResponse]:
    scans = get_user_scans(db, user_id=current_user.id, skip=skip, limit=limit)
    return scans

