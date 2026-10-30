from datetime import datetime
from typing import Any, Dict, Union
from pydantic import BaseModel, ConfigDict, HttpUrl


class URLScanRequest(BaseModel):
    url: HttpUrl


class ScanResponse(BaseModel):
    target: str
    scan_type: str
    risk_level: str
    details: Union[Dict[str, Any], str]

    model_config = ConfigDict(from_attributes=True)


class ScanHistoryResponse(BaseModel):
    id: int
    target: str
    scan_type: str
    risk_level: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
