from typing import Any, Dict
import httpx

from app.core.config import settings

PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/"
PHISHTANK_USER_AGENT = "phishcatch/1.0"


async def check_phishtank(url: str) -> Dict[str, Any]:
    headers = {
        "User-Agent": PHISHTANK_USER_AGENT,
    }

    data: Dict[str, str] = {
        "url": url,
        "format": "json",
    }

    if settings.PHISHTANK_API_KEY:
        data["app_key"] = settings.PHISHTANK_API_KEY

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                PHISHTANK_API_URL,
                headers=headers,
                data=data,
            )
            response.raise_for_status()
            resp_json = response.json()

        results_data = resp_json.get("results", resp_json)
        in_database = bool(results_data.get("in_database", False))
        valid = bool(results_data.get("valid", False))

        if in_database and valid:
            risk_level = "malicious"
        else:
            risk_level = "safe"

        return {
            "risk_level": risk_level,
            "details": resp_json,
        }

    except httpx.TimeoutException:
        return {
            "risk_level": "unknown",
            "error": "Tiempo de espera agotado al conectar con PhishTank.",
            "details": {},
        }
    except httpx.HTTPStatusError as exc:
        return {
            "risk_level": "unknown",
            "error": f"Error HTTP {exc.response.status_code} al consultar PhishTank.",
            "details": {},
        }
    except httpx.RequestError as exc:
        return {
            "risk_level": "unknown",
            "error": f"Error de red o comunicación con PhishTank: {str(exc)}",
            "details": {},
        }
    except Exception as exc:
        return {
            "risk_level": "unknown",
            "error": f"Error inesperado al procesar respuesta de PhishTank: {str(exc)}",
            "details": {},
        }

