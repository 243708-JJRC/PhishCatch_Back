import asyncio
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.crud.crud_scan import create_scan_history
from app.db.session import get_db
from app.models.user import User
from app.schemas.scan import ScanResponse, URLScanRequest
from app.services.email_parser import parse_eml
from app.services.google_safebrowsing import check_safe_browsing
from app.services.virustotal import virustotal_service

router = APIRouter()

MAX_EML_SIZE_BYTES = 10 * 1024 * 1024


def calculate_consensus_risk(vt_risk: str, google_risk: str) -> str:
    if vt_risk == "malicious" or google_risk == "malicious":
        return "malicious"
    if vt_risk == "suspicious" or google_risk == "suspicious":
        return "suspicious"
    if vt_risk in ("error", "unknown") and google_risk in ("error", "unknown"):
        return "error"
    if vt_risk == "safe" or google_risk == "safe":
        return "safe"
    return "safe"


async def scan_url_combined(url: str) -> Dict[str, Any]:
    vt_res, google_res = await asyncio.gather(
        virustotal_service.scan_url(url),
        check_safe_browsing(url),
        return_exceptions=True,
    )

    if isinstance(vt_res, HTTPException):
        vt_data = {"risk_level": "error", "error": vt_res.detail}
        vt_risk = "error"
    elif isinstance(vt_res, Exception):
        vt_data = {"risk_level": "error", "error": str(vt_res)}
        vt_risk = "error"
    else:
        vt_data = vt_res
        vt_risk = vt_res.get("risk_level", "unknown")

    if isinstance(google_res, Exception):
        google_data = {"risk_level": "error", "error": str(google_res)}
        google_risk = "error"
    else:
        google_data = google_res
        google_risk = google_res.get("risk_level", "unknown")

    combined_risk = calculate_consensus_risk(vt_risk, google_risk)

    return {
        "url": url,
        "risk_level": combined_risk,
        "details": {
            "virustotal": vt_data,
            "google": google_data,
        },
    }


@router.post(
    "/url",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Analizar URL sospechosa con VirusTotal y Google Safe Browsing",
)
async def scan_url(
    scan_in: URLScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Any:
    url_str = str(scan_in.url)

    combined_scan = await scan_url_combined(url_str)
    global_risk = combined_scan["risk_level"]
    details = combined_scan["details"]

    create_scan_history(
        db=db,
        user_id=current_user.id,
        target=url_str,
        scan_type="url",
        risk_level=global_risk,
        raw_result=details,
    )

    return ScanResponse(
        target=url_str,
        scan_type="url",
        risk_level=global_risk,
        details=details,
    )


@router.post(
    "/email",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Análisis forense de correo electrónico (.eml)",
)
async def scan_email(
    file: UploadFile = File(..., description="Archivo de correo electrónico en formato .eml"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Any:
    filename = file.filename or "correo_analizado.eml"
    if not filename.lower().endswith(".eml") and file.content_type not in (
        "message/rfc822",
        "application/octet-stream",
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tipo de archivo no admitido. Debe ser un archivo de correo con extensión .eml",
        )

    try:
        file_bytes = await file.read()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error al leer el archivo subido: {str(exc)}",
        )

    if len(file_bytes) > MAX_EML_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="El archivo excede el tamaño máximo permitido de 10 MB.",
        )

    parsed_email = parse_eml(file_bytes)
    security_headers = parsed_email["security_headers"]
    extracted_urls = parsed_email["urls"]

    urls_to_scan = extracted_urls[:5]
    urls_scan_results: List[Dict[str, Any]] = []

    if urls_to_scan:
        tasks = [scan_url_combined(u) for u in urls_to_scan]
        urls_scan_results = await asyncio.gather(*tasks)

    malicious_count = sum(1 for r in urls_scan_results if r.get("risk_level") == "malicious")
    suspicious_count = sum(1 for r in urls_scan_results if r.get("risk_level") == "suspicious")

    spf_status = security_headers.get("spf", "none")
    dkim_status = security_headers.get("dkim", "none")
    dmarc_status = security_headers.get("dmarc", "none")

    if malicious_count > 0:
        global_risk = "malicious"
    elif suspicious_count > 0 or (spf_status == "fail" and dkim_status == "fail"):
        global_risk = "suspicious"
    elif spf_status == "fail" or dkim_status == "fail":
        global_risk = "suspicious"
    else:
        global_risk = "safe"

    details: Dict[str, Any] = {
        "metadata": parsed_email["metadata"],
        "security_headers": {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
        },
        "urls_found": parsed_email["urls_count"],
        "urls_scanned": len(urls_scan_results),
        "malicious_urls": malicious_count,
        "suspicious_urls": suspicious_count,
        "urls_details": urls_scan_results,
    }

    raw_payload: Dict[str, Any] = {
        "parsed_email": parsed_email,
        "urls_scan_results": urls_scan_results,
        "global_risk": global_risk,
    }

    create_scan_history(
        db=db,
        user_id=current_user.id,
        target=filename,
        scan_type="file",
        risk_level=global_risk,
        raw_result=raw_payload,
    )

    return ScanResponse(
        target=filename,
        scan_type="file",
        risk_level=global_risk,
        details=details,
    )
