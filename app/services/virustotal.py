import asyncio
import base64
from typing import Any, Dict
from fastapi import HTTPException, status
import httpx

from app.core.config import settings


class VirusTotalService:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self) -> None:
        self.api_key = settings.VIRUSTOTAL_API_KEY

    def _get_url_id(self, url: str) -> str:
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def _evaluate_risk(self, stats: Dict[str, int]) -> str:
        """
        - 'malicious': Consenso claro (>= 3 motores maliciosos).
        - 'suspicious': 1 o 2 motores maliciosos sin reputación alta, o múltiples sospechosos.
        - 'safe': Sin detecciones, o falsos positivos aislados (1 motor) en dominios masivos (harmless >= 30).
        """
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        # Consenso de amenaza confirmada
        if malicious >= 3:
            return "malicious"

        # Detecciones aisladas (1 o 2 motores)
        if malicious in (1, 2):
            if harmless >= 30:
                return "safe"
            return "suspicious"

        # Motores sospechosos
        if suspicious >= 2:
            return "suspicious"
        if suspicious == 1:
            if harmless >= 30:
                return "safe"
            return "suspicious"

        return "safe"

    async def _poll_analysis(
        self,
        client: httpx.AsyncClient,
        analysis_id: str,
        headers: Dict[str, str],
        max_attempts: int = 6,
        interval_seconds: int = 3,
    ) -> Dict[str, Any]:

        for attempt in range(1, max_attempts + 1):
            await asyncio.sleep(interval_seconds)

            try:
                res = await client.get(
                    f"{self.BASE_URL}/analyses/{analysis_id}",
                    headers=headers,
                )
            except httpx.RequestError as exc:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Fallo de conexión durante el sondeo a VirusTotal: {str(exc)}",
                )

            if res.status_code == 401:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="La API Key de VirusTotal es inválida o ha expirado.",
                )
            if res.status_code == 429:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Límite de cuota alcanzado en VirusTotal durante el sondeo.",
                )

            if res.status_code == 200:
                analysis_data = res.json().get("data", {})
                attributes = analysis_data.get("attributes", {})
                current_status = attributes.get("status")

                if current_status == "completed":
                    stats = attributes.get("stats") or attributes.get("last_analysis_stats") or {}
                    risk_level = self._evaluate_risk(stats)
                    return {
                        "risk_level": risk_level,
                        "stats": stats,
                        "status": "completed",
                        "raw": analysis_data,
                    }

        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Tiempo de espera agotado: El análisis en VirusTotal continúa en estado 'pending' tras múltiples intentos.",
        )

    async def scan_url(self, url: str) -> Dict[str, Any]:
        if not self.api_key:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="La API Key de VirusTotal no está configurada en el servidor (VIRUSTOTAL_API_KEY).",
            )

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }
        url_id = self._get_url_id(url)

        async with httpx.AsyncClient(timeout=20.0) as client:
            try:
                response = await client.get(
                    f"{self.BASE_URL}/urls/{url_id}",
                    headers=headers,
                )

                if response.status_code == 404:
                    post_res = await client.post(
                        f"{self.BASE_URL}/urls",
                        headers=headers,
                        data={"url": url},
                    )
                    if post_res.status_code in (200, 201):
                        analysis_id = post_res.json().get("data", {}).get("id")
                        if analysis_id:
                            return await self._poll_analysis(client, analysis_id, headers)
                    post_res.raise_for_status()

                if response.status_code == 401:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail="La API Key de VirusTotal es inválida o ha expirado.",
                    )
                if response.status_code == 429:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Límite de cuota de peticiones alcanzado en VirusTotal.",
                    )

                response.raise_for_status()
                data = response.json().get("data", {})
                data_type = data.get("type")
                attributes = data.get("attributes", {})

                status_value = attributes.get("status")
                last_stats = attributes.get("last_analysis_stats")

                if data_type == "analysis" or status_value in ("queued", "in-progress", "pending") or not last_stats:
                    analysis_id = data.get("id")
                    if analysis_id:
                        return await self._poll_analysis(client, analysis_id, headers)

                stats = last_stats or attributes.get("stats") or {}
                risk_level = self._evaluate_risk(stats)

                return {
                    "risk_level": risk_level,
                    "stats": stats,
                    "reputation": attributes.get("reputation", 0),
                    "categories": attributes.get("categories", {}),
                    "last_analysis_date": attributes.get("last_analysis_date"),
                    "raw": data,
                }

            except httpx.TimeoutException:
                raise HTTPException(
                    status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                    detail="Tiempo de espera agotado al conectar con VirusTotal.",
                )
            except httpx.RequestError as exc:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Error en la comunicación con VirusTotal: {str(exc)}",
                )


virustotal_service = VirusTotalService()
